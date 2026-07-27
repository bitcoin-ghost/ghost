use crate::config::ReaperConfig;
use crate::verdict::{AnalysisLocation, DeadCodeRegion, DeadCodeType};

/// Core dead code detection engine. Walks raw script bytes to find:
/// - OP_FALSE OP_IF ... OP_ENDIF envelopes (inscriptions)
/// - OP_DROP data stuffing (large push + DROP)
/// - Unreachable code after OP_RETURN
///
/// Returns byte-offset regions of detected dead code.
pub(crate) fn detect_dead_code(
    script_bytes: &[u8],
    input_index: usize,
    config: &ReaperConfig,
) -> Vec<DeadCodeRegion> {
    let mut regions = Vec::new();
    let len = script_bytes.len();
    let mut pos = 0;

    // State for OP_FALSE OP_IF detection
    let mut prev_was_false = false;
    let mut prev_push_size: usize = 0;
    let mut prev_push_offset: usize = 0;

    while pos < len {
        let opcode = script_bytes[pos];

        match opcode {
            // OP_0 (OP_FALSE) — pushes empty byte array (falsy)
            0x00 => {
                prev_was_false = true;
                prev_push_size = 0;
                prev_push_offset = pos;
                pos += 1;
            }

            // OP_PUSHBYTES_1 through OP_PUSHBYTES_75
            0x01..=0x4b => {
                let push_len = opcode as usize;
                if pos + 1 + push_len > len {
                    break; // malformed
                }
                let data = &script_bytes[pos + 1..pos + 1 + push_len];
                prev_was_false = is_false_value(data);
                prev_push_size = push_len;
                prev_push_offset = pos;
                pos += 1 + push_len;
            }

            // OP_PUSHDATA1
            0x4c => {
                if pos + 1 >= len {
                    break;
                }
                let push_len = script_bytes[pos + 1] as usize;
                if pos + 2 + push_len > len {
                    break;
                }
                let data = &script_bytes[pos + 2..pos + 2 + push_len];
                prev_was_false = is_false_value(data);
                prev_push_size = push_len;
                prev_push_offset = pos;
                pos += 2 + push_len;
            }

            // OP_PUSHDATA2
            0x4d => {
                if pos + 2 >= len {
                    break;
                }
                let push_len =
                    u16::from_le_bytes([script_bytes[pos + 1], script_bytes[pos + 2]]) as usize;
                if pos + 3 + push_len > len {
                    break;
                }
                let data = &script_bytes[pos + 3..pos + 3 + push_len];
                prev_was_false = is_false_value(data);
                prev_push_size = push_len;
                prev_push_offset = pos;
                pos += 3 + push_len;
            }

            // OP_PUSHDATA4
            0x4e => {
                if pos + 4 >= len {
                    break;
                }
                let push_len = u32::from_le_bytes([
                    script_bytes[pos + 1],
                    script_bytes[pos + 2],
                    script_bytes[pos + 3],
                    script_bytes[pos + 4],
                ]) as usize;
                if pos + 5 + push_len > len {
                    break;
                }
                let data = &script_bytes[pos + 5..pos + 5 + push_len];
                prev_was_false = is_false_value(data);
                prev_push_size = push_len;
                prev_push_offset = pos;
                pos += 5 + push_len;
            }

            // OP_1NEGATE — pushes -1, truthy value
            0x4f => {
                prev_was_false = false;
                prev_push_size = 0;
                prev_push_offset = pos;
                pos += 1;
            }

            // OP_1 through OP_16 — push small integers, all truthy
            0x51..=0x60 => {
                prev_was_false = false;
                prev_push_size = 0;
                prev_push_offset = pos;
                pos += 1;
            }

            // OP_IF — check if preceded by false value
            0x63 => {
                if prev_was_false && config.reject_inscription_envelope {
                    // Found OP_FALSE OP_IF — scan for matching OP_ENDIF
                    let envelope_start = prev_push_offset;
                    pos += 1; // move past OP_IF
                    let mut depth: usize = 1;

                    while pos < len && depth > 0 {
                        let inner = script_bytes[pos];
                        match inner {
                            // Nested OP_IF or OP_NOTIF
                            0x63 | 0x64 => {
                                depth += 1;
                                pos += 1;
                            }
                            // OP_ENDIF
                            0x68 => {
                                depth -= 1;
                                pos += 1;
                            }
                            // Skip push data inside dead region
                            0x01..=0x4b => {
                                let skip = inner as usize;
                                pos += 1 + skip;
                            }
                            0x4c => {
                                if pos + 1 < len {
                                    let skip = script_bytes[pos + 1] as usize;
                                    pos += 2 + skip;
                                } else {
                                    pos = len;
                                }
                            }
                            0x4d => {
                                if pos + 2 < len {
                                    let skip = u16::from_le_bytes([
                                        script_bytes[pos + 1],
                                        script_bytes[pos + 2],
                                    ]) as usize;
                                    pos += 3 + skip;
                                } else {
                                    pos = len;
                                }
                            }
                            0x4e => {
                                if pos + 4 < len {
                                    let skip = u32::from_le_bytes([
                                        script_bytes[pos + 1],
                                        script_bytes[pos + 2],
                                        script_bytes[pos + 3],
                                        script_bytes[pos + 4],
                                    ]) as usize;
                                    pos += 5 + skip;
                                } else {
                                    pos = len;
                                }
                            }
                            _ => {
                                pos += 1;
                            }
                        }
                    }

                    let envelope_size = pos - envelope_start;
                    regions.push(DeadCodeRegion {
                        location: AnalysisLocation::Input(input_index),
                        dead_code_type: DeadCodeType::InscriptionEnvelope,
                        offset: envelope_start,
                        size: envelope_size,
                        description: format!(
                            "OP_FALSE OP_IF envelope: {} bytes of dead code",
                            envelope_size
                        ),
                    });
                } else {
                    pos += 1;
                }
                prev_was_false = false;
                prev_push_size = 0;
            }

            // OP_DROP (0x75) — check if preceded by large push
            0x75 => {
                if config.reject_drop_stuffing && prev_push_size >= config.min_drop_data_size {
                    let region_size = pos - prev_push_offset + 1; // includes the DROP
                    regions.push(DeadCodeRegion {
                        location: AnalysisLocation::Input(input_index),
                        dead_code_type: DeadCodeType::DropStuffing,
                        offset: prev_push_offset,
                        size: region_size,
                        description: format!(
                            "OP_DROP data stuffing: {} byte push immediately dropped",
                            prev_push_size
                        ),
                    });
                }
                prev_was_false = false;
                prev_push_size = 0;
                pos += 1;
            }

            // OP_2DROP (0x6d) — pops two items; check if preceded by large push
            0x6d => {
                if config.reject_drop_stuffing && prev_push_size >= config.min_drop_data_size {
                    let region_size = pos - prev_push_offset + 1;
                    regions.push(DeadCodeRegion {
                        location: AnalysisLocation::Input(input_index),
                        dead_code_type: DeadCodeType::DropStuffing,
                        offset: prev_push_offset,
                        size: region_size,
                        description: format!(
                            "OP_2DROP data stuffing: {} byte push immediately dropped",
                            prev_push_size
                        ),
                    });
                }
                prev_was_false = false;
                prev_push_size = 0;
                pos += 1;
            }

            // OP_RETURN (0x6a) — everything after is unreachable
            0x6a => {
                if config.reject_unreachable_code && pos + 1 < len {
                    let remaining = len - (pos + 1);
                    regions.push(DeadCodeRegion {
                        location: AnalysisLocation::Input(input_index),
                        dead_code_type: DeadCodeType::UnreachableCode,
                        offset: pos,
                        size: remaining + 1, // include OP_RETURN itself
                        description: format!(
                            "Unreachable code: {} bytes after OP_RETURN in witness script",
                            remaining
                        ),
                    });
                }
                // Nothing more to parse
                break;
            }

            // Any other opcode — reset push tracking
            _ => {
                prev_was_false = false;
                prev_push_size = 0;
                pos += 1;
            }
        }
    }

    regions
}

/// Check if pushed data evaluates to false in Bitcoin Script.
/// False values: empty, all-zero, or negative zero (0x80 as last byte with zeros before).
pub(crate) fn is_false_value(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // Check for all zeros
    if data.iter().all(|&b| b == 0) {
        return true;
    }
    // Check for negative zero: all zeros except last byte is 0x80
    if !data.is_empty() && data[data.len() - 1] == 0x80 {
        return data[..data.len() - 1].iter().all(|&b| b == 0);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_false_value() {
        assert!(is_false_value(&[]));
        assert!(is_false_value(&[0x00]));
        assert!(is_false_value(&[0x00, 0x00]));
        assert!(is_false_value(&[0x80])); // negative zero
        assert!(is_false_value(&[0x00, 0x80])); // negative zero
        assert!(!is_false_value(&[0x01]));
        assert!(!is_false_value(&[0x00, 0x01]));
    }

    #[test]
    fn test_detect_simple_envelope() {
        // OP_FALSE(0x00) OP_IF(0x63) <push 3 bytes "ord"> OP_ENDIF(0x68) OP_1(0x51)
        let script = vec![0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0x51];
        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::InscriptionEnvelope);
        assert_eq!(regions[0].offset, 0); // starts at OP_FALSE
        assert_eq!(regions[0].size, 7); // 0x00 0x63 0x03 o r d 0x68
    }

    #[test]
    fn test_detect_drop_stuffing() {
        // Push 80 bytes then OP_DROP
        let mut script = vec![0x4c, 80]; // OP_PUSHDATA1, length=80
        script.extend(vec![0xAA; 80]); // 80 bytes of data
        script.push(0x75); // OP_DROP

        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::DropStuffing);
    }

    #[test]
    fn test_no_false_positive_small_drop() {
        // Push 10 bytes (below threshold) then OP_DROP — should NOT flag
        let mut script = vec![10u8]; // OP_PUSHBYTES_10
        script.extend(vec![0xBB; 10]);
        script.push(0x75); // OP_DROP

        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_detect_unreachable_after_op_return() {
        // OP_1(0x51) OP_RETURN(0x6a) <dead bytes>
        let script = vec![0x51, 0x6a, 0xDE, 0xAD, 0xBE, 0xEF];
        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::UnreachableCode);
        assert_eq!(regions[0].offset, 1); // OP_RETURN position
        assert_eq!(regions[0].size, 5); // OP_RETURN + 4 dead bytes
    }

    #[test]
    fn test_nested_if_depth() {
        // OP_FALSE OP_IF OP_IF OP_ENDIF OP_ENDIF OP_1
        let script = vec![0x00, 0x63, 0x63, 0x68, 0x68, 0x51];
        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].size, 5); // 0x00 0x63 0x63 0x68 0x68
    }

    #[test]
    fn test_push_0x00_circumvention() {
        // OP_PUSHBYTES_1(0x01) 0x00 OP_IF ... — this pushes [0x00] which is falsy
        let script = vec![0x01, 0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68];
        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::InscriptionEnvelope);
    }

    #[test]
    fn test_negative_zero_circumvention() {
        // OP_PUSHBYTES_1(0x01) 0x80 OP_IF ... — pushes [0x80] (negative zero, falsy)
        let script = vec![0x01, 0x80, 0x63, 0x03, b'o', b'r', b'd', 0x68];
        let config = ReaperConfig::default();
        let regions = detect_dead_code(&script, 0, &config);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::InscriptionEnvelope);
    }
}
