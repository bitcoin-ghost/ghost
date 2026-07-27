//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: legacy.rs                                                                                                      |
//|======================================================================================================================|

use crate::config::ReaperConfig;
use crate::dead_code::detect_dead_code;
use crate::verdict::{AnalysisLocation, DeadCodeRegion, DeadCodeType};

/// Analyze a legacy scriptSig for data stuffing.
///
/// Parses scriptSig as a sequence of pushes. Legitimate pushes are:
/// - DER signatures (71-73 bytes, starts with 0x30)
/// - Compressed pubkeys (33 bytes, starts with 0x02/0x03)
/// - Uncompressed pubkeys (65 bytes, starts with 0x04)
/// - P2SH redeemScript (last push containing opcodes — checked for dead code)
///
/// Anything else exceeding `config.legacy_max_push_bytes` is flagged as data stuffing.
pub(crate) fn analyze_legacy_scriptsig(
    script_sig_bytes: &[u8],
    input_index: usize,
    config: &ReaperConfig,
) -> Vec<DeadCodeRegion> {
    let mut regions = Vec::new();
    let len = script_sig_bytes.len();
    if len == 0 {
        return regions;
    }

    // Parse all pushes first
    let pushes = parse_pushes(script_sig_bytes);
    if pushes.is_empty() {
        return regions;
    }

    // Last push might be a P2SH redeemScript — check it for dead code
    let last = &pushes[pushes.len() - 1];
    if last.size > 1
        && looks_like_redeem_script(&script_sig_bytes[last.data_start..last.data_start + last.size])
    {
        let redeem_script = &script_sig_bytes[last.data_start..last.data_start + last.size];
        let inner_regions = detect_dead_code(redeem_script, input_index, config);
        // Adjust offsets: inner regions are relative to the redeemScript start,
        // we need them relative to the scriptSig start
        for mut region in inner_regions {
            region.offset += last.data_start;
            regions.push(region);
        }
    }

    // Check non-last pushes for data stuffing
    let check_end = if pushes.len() > 1 {
        pushes.len() - 1
    } else {
        // If there's only one push, still check it (unless it's a redeemScript)
        if looks_like_redeem_script(&script_sig_bytes[last.data_start..last.data_start + last.size])
        {
            return regions;
        }
        pushes.len()
    };

    for push in &pushes[..check_end] {
        if push.size <= config.legacy_max_push_bytes {
            continue;
        }

        let data = &script_sig_bytes[push.data_start..push.data_start + push.size];

        // Skip legitimate push types
        if is_der_signature(data) || is_compressed_pubkey(data) || is_uncompressed_pubkey(data) {
            continue;
        }

        // Large non-signature, non-pubkey push → data stuffing
        regions.push(DeadCodeRegion {
            location: AnalysisLocation::Input(input_index),
            dead_code_type: DeadCodeType::LegacyScriptSigData,
            offset: push.push_start,
            size: push.total_bytes,
            description: format!(
                "Legacy scriptSig data stuffing: {} byte push (not sig/pubkey)",
                push.size
            ),
        });
    }

    regions
}

struct PushInfo {
    push_start: usize,  // Start of the push opcode
    data_start: usize,  // Start of the pushed data
    size: usize,        // Size of the pushed data
    total_bytes: usize, // Total bytes consumed (opcode + length + data)
}

/// Parse all push operations in a script.
fn parse_pushes(script: &[u8]) -> Vec<PushInfo> {
    let mut pushes = Vec::new();
    let len = script.len();
    let mut pos = 0;

    while pos < len {
        let opcode = script[pos];
        match opcode {
            // OP_PUSHBYTES_1..75
            0x01..=0x4b => {
                let push_len = opcode as usize;
                if pos + 1 + push_len > len {
                    break;
                }
                pushes.push(PushInfo {
                    push_start: pos,
                    data_start: pos + 1,
                    size: push_len,
                    total_bytes: 1 + push_len,
                });
                pos += 1 + push_len;
            }
            // OP_PUSHDATA1
            0x4c => {
                if pos + 1 >= len {
                    break;
                }
                let push_len = script[pos + 1] as usize;
                if pos + 2 + push_len > len {
                    break;
                }
                pushes.push(PushInfo {
                    push_start: pos,
                    data_start: pos + 2,
                    size: push_len,
                    total_bytes: 2 + push_len,
                });
                pos += 2 + push_len;
            }
            // OP_PUSHDATA2
            0x4d => {
                if pos + 2 >= len {
                    break;
                }
                let push_len = u16::from_le_bytes([script[pos + 1], script[pos + 2]]) as usize;
                if pos + 3 + push_len > len {
                    break;
                }
                pushes.push(PushInfo {
                    push_start: pos,
                    data_start: pos + 3,
                    size: push_len,
                    total_bytes: 3 + push_len,
                });
                pos += 3 + push_len;
            }
            // OP_PUSHDATA4
            0x4e => {
                if pos + 4 >= len {
                    break;
                }
                let push_len = u32::from_le_bytes([
                    script[pos + 1],
                    script[pos + 2],
                    script[pos + 3],
                    script[pos + 4],
                ]) as usize;
                if pos + 5 + push_len > len {
                    break;
                }
                pushes.push(PushInfo {
                    push_start: pos,
                    data_start: pos + 5,
                    size: push_len,
                    total_bytes: 5 + push_len,
                });
                pos += 5 + push_len;
            }
            // OP_0 (empty push)
            0x00 => {
                pushes.push(PushInfo {
                    push_start: pos,
                    data_start: pos + 1, // no data
                    size: 0,
                    total_bytes: 1,
                });
                pos += 1;
            }
            // Any non-push opcode — stop parsing (scriptSig should be pushes only)
            _ => {
                pos += 1;
            }
        }
    }

    pushes
}

/// Check if data is a DER-encoded signature (71-73 bytes, starts with 0x30).
fn is_der_signature(data: &[u8]) -> bool {
    (71..=73).contains(&data.len()) && data[0] == 0x30
}

/// Check if data is a compressed pubkey (33 bytes, starts with 0x02/0x03).
fn is_compressed_pubkey(data: &[u8]) -> bool {
    data.len() == 33 && (data[0] == 0x02 || data[0] == 0x03)
}

/// Check if data is an uncompressed pubkey (65 bytes, starts with 0x04).
fn is_uncompressed_pubkey(data: &[u8]) -> bool {
    data.len() == 65 && data[0] == 0x04
}

/// Heuristic: does this look like a P2SH redeemScript?
/// A redeemScript contains opcodes (not just data). Check if the last byte
/// is a common script-terminating opcode.
fn looks_like_redeem_script(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let last = data[data.len() - 1];
    // Common terminal opcodes in redeemScripts
    matches!(
        last,
        0xac  // OP_CHECKSIG
        | 0xad // OP_CHECKSIGVERIFY
        | 0xae // OP_CHECKMULTISIG
        | 0xaf // OP_CHECKMULTISIGVERIFY
        | 0x87 // OP_EQUAL
        | 0x88 // OP_EQUALVERIFY
        | 0x68 // OP_ENDIF
        | 0x69 // OP_VERIFY
        | 0xb1 // OP_CLTV
        | 0xb2 // OP_CSV
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_der_signature() {
        let mut sig = vec![0x30];
        sig.extend(vec![0x44; 71]); // 72 total
        assert!(is_der_signature(&sig));

        let short = vec![0x30; 10];
        assert!(!is_der_signature(&short));
    }

    #[test]
    fn test_is_compressed_pubkey() {
        let mut pk = vec![0x02];
        pk.extend(vec![0xAA; 32]);
        assert!(is_compressed_pubkey(&pk));

        let mut pk03 = vec![0x03];
        pk03.extend(vec![0xBB; 32]);
        assert!(is_compressed_pubkey(&pk03));
    }

    #[test]
    fn test_parse_pushes_basic() {
        // PUSHBYTES_3 "abc"
        let script = vec![0x03, b'a', b'b', b'c'];
        let pushes = parse_pushes(&script);
        assert_eq!(pushes.len(), 1);
        assert_eq!(pushes[0].size, 3);
    }

    #[test]
    fn test_data_stuffing_detection() {
        // Construct a scriptSig with a 200-byte non-sig push followed by a sig + pubkey
        let mut script_sig = Vec::new();

        // 200-byte data push (not a sig or pubkey)
        script_sig.push(0x4c); // OP_PUSHDATA1
        script_sig.push(200);
        script_sig.extend(vec![0xDD; 200]);

        // Legitimate DER signature (72 bytes)
        let mut sig = vec![0x30];
        sig.extend(vec![0x44; 71]);
        script_sig.push(sig.len() as u8);
        script_sig.extend(&sig);

        let config = ReaperConfig::default();
        let regions = analyze_legacy_scriptsig(&script_sig, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::LegacyScriptSigData);
    }
}
