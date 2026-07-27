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
//| FILE: flow.rs                                                                                                        |
//|======================================================================================================================|

use crate::dead_code::is_false_value;
use crate::verdict::{AnalysisLocation, DeadCodeRegion, DeadCodeType};

/// Minimum data push size for push-drop detection (bytes).
/// Pushes below this threshold are likely legitimate (e.g., timelock + OP_DROP).
const MIN_DROP_DATA_SIZE: usize = 76;

/// Analyze a script for dead code using control flow semantics.
///
/// Three detectors run independently of pattern-based config toggles:
/// 1. Dead branches — constant-conditional IF/NOTIF with provably untaken paths
/// 2. Dead push-drop pairs — large pushes immediately consumed by DROP/2DROP
/// 3. Post-OP_RETURN code — unreachable bytes after top-level OP_RETURN
pub(crate) fn analyze_script_flow(script: &[u8], input_index: usize) -> Vec<DeadCodeRegion> {
    let ops = parse_ops(script);
    let mut regions = Vec::new();

    regions.extend(detect_dead_branches(&ops, script, input_index));
    regions.extend(detect_dead_push_drops(&ops, input_index));
    regions.extend(detect_dead_after_return(&ops, script, input_index));

    regions
}

// ── Opcode Parser ────────────────────────────────────────────────────────────

pub(crate) struct ScriptOp {
    pub(crate) offset: usize,
    pub(crate) size: usize,
    pub(crate) opcode: u8,
    /// For push ops (0x00-0x4e), the number of data bytes pushed. Otherwise 0.
    pub(crate) data_size: usize,
}

pub(crate) fn parse_ops(script: &[u8]) -> Vec<ScriptOp> {
    let mut ops = Vec::new();
    let len = script.len();
    let mut pos = 0;

    while pos < len {
        let opcode = script[pos];
        let (size, data_size) = match opcode {
            0x00 => (1, 0),
            0x01..=0x4b => {
                let n = opcode as usize;
                if pos + 1 + n > len {
                    break;
                }
                (1 + n, n)
            }
            0x4c => {
                if pos + 1 >= len {
                    break;
                }
                let n = script[pos + 1] as usize;
                if pos + 2 + n > len {
                    break;
                }
                (2 + n, n)
            }
            0x4d => {
                if pos + 2 >= len {
                    break;
                }
                let n = u16::from_le_bytes([script[pos + 1], script[pos + 2]]) as usize;
                if pos + 3 + n > len {
                    break;
                }
                (3 + n, n)
            }
            0x4e => {
                if pos + 4 >= len {
                    break;
                }
                let n = u32::from_le_bytes([
                    script[pos + 1],
                    script[pos + 2],
                    script[pos + 3],
                    script[pos + 4],
                ]) as usize;
                if pos + 5 + n > len {
                    break;
                }
                (5 + n, n)
            }
            _ => (1, 0),
        };
        ops.push(ScriptOp {
            offset: pos,
            size,
            opcode,
            data_size,
        });
        pos += size;
    }

    ops
}

// ── Detector 1: Dead Branches ────────────────────────────────────────────────

fn detect_dead_branches(
    ops: &[ScriptOp],
    script: &[u8],
    input_index: usize,
) -> Vec<DeadCodeRegion> {
    let mut regions = Vec::new();

    for i in 0..ops.len() {
        if ops[i].opcode != 0x63 && ops[i].opcode != 0x64 {
            continue;
        }
        if i == 0 {
            continue;
        }

        let is_notif = ops[i].opcode == 0x64;
        let prev = &ops[i - 1];

        let (is_const, is_false) = classify_push(prev, script);
        if !is_const {
            continue;
        }

        // IF: body dead when condition false. NOTIF: body dead when condition true.
        let body_dead = if is_notif { !is_false } else { is_false };

        let (else_idx, endif_idx) = find_else_endif(ops, i);
        let Some(endif_idx) = endif_idx else {
            continue;
        };

        if body_dead {
            if let Some(else_idx) = else_idx {
                // FALSE IF <dead> ELSE <live> ENDIF
                // Region 1: condition push through ELSE (inclusive)
                let start = prev.offset;
                let end = ops[else_idx].offset + ops[else_idx].size;
                regions.push(make_region(
                    input_index,
                    start,
                    end - start,
                    DeadCodeType::InscriptionEnvelope,
                    format!(
                        "Dead branch: {} bytes (constant-false condition, IF body unreachable)",
                        end - start
                    ),
                ));
                // Region 2: ENDIF
                let endif_op = &ops[endif_idx];
                regions.push(make_region(
                    input_index,
                    endif_op.offset,
                    endif_op.size,
                    DeadCodeType::InscriptionEnvelope,
                    "Dead branch: ENDIF overhead".to_string(),
                ));
            } else {
                // FALSE IF <dead> ENDIF (no ELSE) — entire construct is dead
                let start = prev.offset;
                let end = ops[endif_idx].offset + ops[endif_idx].size;
                regions.push(make_region(
                    input_index,
                    start,
                    end - start,
                    DeadCodeType::InscriptionEnvelope,
                    format!(
                        "Dead branch: {} bytes (constant-false condition, entire IF block unreachable)",
                        end - start
                    ),
                ));
            }
        } else if let Some(else_idx) = else_idx {
            // TRUE IF <live> ELSE <dead> ENDIF
            // Region 1: condition push + IF
            let start = prev.offset;
            let end = ops[i].offset + ops[i].size;
            regions.push(make_region(
                input_index,
                start,
                end - start,
                DeadCodeType::InscriptionEnvelope,
                "Dead branch: condition push + IF overhead".to_string(),
            ));
            // Region 2: ELSE through ENDIF (inclusive)
            let else_start = ops[else_idx].offset;
            let else_end = ops[endif_idx].offset + ops[endif_idx].size;
            regions.push(make_region(
                input_index,
                else_start,
                else_end - else_start,
                DeadCodeType::InscriptionEnvelope,
                format!(
                    "Dead branch: {} bytes (constant-true condition, ELSE body unreachable)",
                    else_end - else_start
                ),
            ));
        }
        // TRUE IF <live> ENDIF (no ELSE): only overhead is dead (2-3 bytes), skip
    }

    regions
}

/// Classify a push opcode: returns (is_constant_push, is_false_value).
fn classify_push(op: &ScriptOp, script: &[u8]) -> (bool, bool) {
    match op.opcode {
        0x00 => (true, true),
        0x01..=0x4b => {
            let data = &script[op.offset + 1..op.offset + 1 + op.data_size];
            (true, is_false_value(data))
        }
        0x4c => {
            let data = &script[op.offset + 2..op.offset + op.size];
            (true, is_false_value(data))
        }
        0x4d => {
            let data = &script[op.offset + 3..op.offset + op.size];
            (true, is_false_value(data))
        }
        0x4e => {
            let data = &script[op.offset + 5..op.offset + op.size];
            (true, is_false_value(data))
        }
        0x4f => (true, false),        // OP_1NEGATE (truthy)
        0x51..=0x60 => (true, false), // OP_1..OP_16 (all truthy)
        _ => (false, false),
    }
}

/// Find the matching ELSE and ENDIF for an IF/NOTIF at `if_idx`.
pub(crate) fn find_else_endif(ops: &[ScriptOp], if_idx: usize) -> (Option<usize>, Option<usize>) {
    let mut depth: usize = 1;
    let mut else_idx = None;

    for (j, op) in ops.iter().enumerate().skip(if_idx + 1) {
        match op.opcode {
            0x63 | 0x64 => depth += 1,
            0x67 if depth == 1 => else_idx = Some(j),
            0x68 => {
                depth -= 1;
                if depth == 0 {
                    return (else_idx, Some(j));
                }
            }
            _ => {}
        }
    }

    (else_idx, None)
}

// ── Detector 2: Dead Push-Drop Pairs ─────────────────────────────────────────

fn detect_dead_push_drops(ops: &[ScriptOp], input_index: usize) -> Vec<DeadCodeRegion> {
    let mut regions = Vec::new();

    for i in 0..ops.len() {
        match ops[i].opcode {
            // OP_DROP
            0x75 if i > 0 => {
                let prev = &ops[i - 1];
                if is_push_opcode(prev.opcode) && prev.data_size >= MIN_DROP_DATA_SIZE {
                    let start = prev.offset;
                    let end = ops[i].offset + ops[i].size;
                    regions.push(make_region(
                        input_index,
                        start,
                        end - start,
                        DeadCodeType::DropStuffing,
                        format!(
                            "Push-drop: {} byte push immediately dropped",
                            prev.data_size
                        ),
                    ));
                }
            }
            // OP_2DROP
            0x6d if i >= 2 => {
                let p1 = &ops[i - 2];
                let p2 = &ops[i - 1];
                if is_push_opcode(p1.opcode) && is_push_opcode(p2.opcode) {
                    let max_data = p1.data_size.max(p2.data_size);
                    if max_data >= MIN_DROP_DATA_SIZE {
                        let start = p1.offset;
                        let end = ops[i].offset + ops[i].size;
                        regions.push(make_region(
                            input_index,
                            start,
                            end - start,
                            DeadCodeType::DropStuffing,
                            format!(
                                "Push-2drop: {} + {} byte pushes immediately dropped",
                                p1.data_size, p2.data_size
                            ),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    regions
}

fn is_push_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x00..=0x4e | 0x4f | 0x51..=0x60)
}

// ── Detector 3: Post-OP_RETURN ───────────────────────────────────────────────

fn detect_dead_after_return(
    ops: &[ScriptOp],
    script: &[u8],
    input_index: usize,
) -> Vec<DeadCodeRegion> {
    let mut if_depth: usize = 0;

    for op in ops {
        match op.opcode {
            0x63 | 0x64 => if_depth += 1,
            0x68 => if_depth = if_depth.saturating_sub(1),
            0x6a if if_depth == 0 => {
                let remaining = script.len() - op.offset;
                if remaining > 1 {
                    return vec![make_region(
                        input_index,
                        op.offset,
                        remaining,
                        DeadCodeType::UnreachableCode,
                        format!("Unreachable: {} bytes after OP_RETURN", remaining - 1),
                    )];
                }
                return Vec::new();
            }
            _ => {}
        }
    }

    Vec::new()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_region(
    input_index: usize,
    offset: usize,
    size: usize,
    dead_code_type: DeadCodeType,
    description: String,
) -> DeadCodeRegion {
    DeadCodeRegion {
        location: AnalysisLocation::Input(input_index),
        dead_code_type,
        offset,
        size,
        description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Dead Branch Tests ────────────────────────────────────────────────

    #[test]
    fn test_false_if_body_endif() {
        // OP_FALSE OP_IF PUSH3 "ord" OP_ENDIF OP_CHECKSIG
        let script = vec![0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::InscriptionEnvelope);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 7); // FALSE through ENDIF
    }

    #[test]
    fn test_false_if_else_endif() {
        // OP_FALSE OP_IF <dead: PUSH1 0xAA> OP_ELSE <live: CHECKSIG> OP_ENDIF
        let script = vec![0x00, 0x63, 0x01, 0xAA, 0x67, 0xac, 0x68];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 2);
        // Region 1: FALSE through ELSE (inclusive)
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 5);
        // Region 2: ENDIF
        assert_eq!(regions[1].offset, 6);
        assert_eq!(regions[1].size, 1);
    }

    #[test]
    fn test_true_if_else_endif() {
        // OP_1 OP_IF <live: CHECKSIG> OP_ELSE <dead: PUSH1 0xBB> OP_ENDIF
        let script = vec![0x51, 0x63, 0xac, 0x67, 0x01, 0xBB, 0x68];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 2);
        // Region 1: OP_1 + IF
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 2);
        // Region 2: ELSE through ENDIF
        assert_eq!(regions[1].offset, 3);
        assert_eq!(regions[1].size, 4);
    }

    #[test]
    fn test_notif_false_condition_body_lives() {
        // OP_FALSE OP_NOTIF <live body: CHECKSIG> OP_ENDIF
        // FALSE + NOTIF = body executes → no dead body, only overhead (skipped)
        let script = vec![0x00, 0x64, 0xac, 0x68];
        let regions = analyze_script_flow(&script, 0);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_notif_true_condition_dead_body() {
        // OP_1 OP_NOTIF PUSH3 "ord" OP_ENDIF OP_CHECKSIG
        // TRUE + NOTIF = body does NOT execute → dead
        let script = vec![0x51, 0x64, 0x03, b'o', b'r', b'd', 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 7);
    }

    #[test]
    fn test_nested_if_in_dead_branch() {
        // OP_FALSE OP_IF OP_IF OP_ENDIF OP_ENDIF OP_CHECKSIG
        let script = vec![0x00, 0x63, 0x63, 0x68, 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        // Outer FALSE IF catches entire construct
        assert!(!regions.is_empty());
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 5);
    }

    #[test]
    fn test_push_0x00_if_detected() {
        // OP_PUSHBYTES_1 0x00 OP_IF ... — pushes [0x00] which is falsy
        let script = vec![0x01, 0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 8); // PUSHBYTES_1 0x00 through ENDIF
    }

    #[test]
    fn test_negative_zero_if_detected() {
        // OP_PUSHBYTES_1 0x80 OP_IF ... — pushes [0x80] (negative zero, falsy)
        let script = vec![0x01, 0x80, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 8);
    }

    #[test]
    fn test_unknown_condition_conservative() {
        // OP_DUP OP_IF ... OP_ENDIF — condition unknown, don't flag
        let script = vec![0x76, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        assert!(regions.is_empty());
    }

    // ── Push-Drop Tests ──────────────────────────────────────────────────

    #[test]
    fn test_push_drop_large() {
        // PUSHDATA1 100 bytes + OP_DROP
        let mut script = vec![0x4c, 100];
        script.extend(vec![0xAA; 100]);
        script.push(0x75);
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::DropStuffing);
        assert_eq!(regions[0].offset, 0);
        assert_eq!(regions[0].size, 103);
    }

    #[test]
    fn test_push_drop_small_skip() {
        // Small push (4 bytes) + OP_DROP — below threshold, legitimate
        let script = vec![0x04, 0x01, 0x02, 0x03, 0x04, 0x75];
        let regions = analyze_script_flow(&script, 0);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_2drop_large_pushes() {
        // Two large pushes + OP_2DROP
        let mut script = vec![0x4c, 80];
        script.extend(vec![0xAA; 80]);
        script.push(0x4c);
        script.push(80);
        script.extend(vec![0xBB; 80]);
        script.push(0x6d);
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::DropStuffing);
    }

    // ── Post-OP_RETURN Tests ─────────────────────────────────────────────

    #[test]
    fn test_op_return_top_level() {
        // OP_1 OP_RETURN <dead bytes>
        let script = vec![0x51, 0x6a, 0xDE, 0xAD, 0xBE, 0xEF];
        let regions = analyze_script_flow(&script, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::UnreachableCode);
        assert_eq!(regions[0].offset, 1);
        assert_eq!(regions[0].size, 5);
    }

    #[test]
    fn test_op_return_inside_if_no_flag() {
        // OP_IF OP_RETURN OP_ENDIF OP_CHECKSIG — inside IF, not top level
        let script = vec![0x63, 0x6a, 0x68, 0xac];
        let regions = analyze_script_flow(&script, 0);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_op_return_bare_no_flag() {
        // OP_RETURN at end of script with nothing after → no dead bytes
        let script = vec![0x51, 0x6a];
        let regions = analyze_script_flow(&script, 0);
        assert!(regions.is_empty());
    }

    // ── Clean Script ─────────────────────────────────────────────────────

    #[test]
    fn test_clean_script_no_flags() {
        let script = vec![0xac]; // OP_CHECKSIG
        let regions = analyze_script_flow(&script, 0);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_empty_script() {
        let regions = analyze_script_flow(&[], 0);
        assert!(regions.is_empty());
    }
}
