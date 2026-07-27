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
//| FILE: essential.rs                                                                                                   |
//|======================================================================================================================|

use std::collections::BTreeSet;

use bitcoin::TxIn;

use crate::simulator::simulate_essential_witnesses;
use crate::verdict::{DeadCodeRegion, WitnessBreakdown};
use crate::witness::SpendType;

/// Strip dead regions from a script, returning the essential bytes and count removed.
///
/// Takes the original script and dead regions identified by `detect_dead_code()`.
/// Removes those regions and concatenates the remaining bytes.
/// The stripped script executes identically for validation purposes.
pub(crate) fn strip_to_essential(
    script_bytes: &[u8],
    dead_regions: &[DeadCodeRegion],
) -> (Vec<u8>, usize) {
    if dead_regions.is_empty() {
        return (script_bytes.to_vec(), 0);
    }

    // Collect (offset, size) pairs for regions within this script, sorted by offset
    let mut ranges: Vec<(usize, usize)> = dead_regions.iter().map(|r| (r.offset, r.size)).collect();
    ranges.sort_by_key(|&(offset, _)| offset);

    let mut essential = Vec::with_capacity(script_bytes.len());
    let mut pos = 0;
    let mut bytes_removed = 0;

    for (offset, size) in &ranges {
        // Clamp to script bounds
        let start = (*offset).min(script_bytes.len());
        let end = (offset + size).min(script_bytes.len());

        if pos < start {
            essential.extend_from_slice(&script_bytes[pos..start]);
        }
        bytes_removed += end.saturating_sub(start.max(pos));
        pos = end.max(pos);
    }

    // Remaining bytes after last dead region
    if pos < script_bytes.len() {
        essential.extend_from_slice(&script_bytes[pos..]);
    }

    (essential, bytes_removed)
}

/// Count the minimum number of witness stack items a script consumes.
///
/// Conservative: counts ALL branches (sums across IF/ELSE paths), so legitimate
/// scripts never get false-positived. This is an upper bound on what the script
/// *might* consume, which means we only flag excess when items truly exceed
/// the maximum any execution path could need.
///
/// For tapscript: OP_CHECKSIG/CHECKSIGADD consume 1 sig from the stack (pubkey is in-script).
/// For P2WSH (non-tapscript): OP_CHECKSIG consumes 1 sig from the stack.
/// OP_CHECKMULTISIG consumes m+1 items (m sigs + 1 dummy).
pub(crate) fn count_stack_consumption(script_bytes: &[u8], is_tapscript: bool) -> usize {
    let len = script_bytes.len();
    let mut pos = 0;
    let mut count: usize = 0;

    while pos < len {
        let opcode = script_bytes[pos];

        match opcode {
            // OP_PUSHBYTES_1..75
            0x01..=0x4b => {
                let push_len = opcode as usize;
                pos += 1 + push_len;
            }
            // OP_PUSHDATA1
            0x4c => {
                if pos + 1 >= len {
                    break;
                }
                let push_len = script_bytes[pos + 1] as usize;
                pos += 2 + push_len;
            }
            // OP_PUSHDATA2
            0x4d => {
                if pos + 2 >= len {
                    break;
                }
                let push_len =
                    u16::from_le_bytes([script_bytes[pos + 1], script_bytes[pos + 2]]) as usize;
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
                pos += 5 + push_len;
            }

            // OP_CHECKSIG (0xac) / OP_CHECKSIGVERIFY (0xad) — 1 sig from stack
            0xac | 0xad => {
                count += 1;
                pos += 1;
            }

            // OP_CHECKSIGADD (0xba) — tapscript only, 1 sig from stack
            0xba if is_tapscript => {
                count += 1;
                pos += 1;
            }

            // OP_CHECKMULTISIG (0xae) / OP_CHECKMULTISIGVERIFY (0xaf)
            // Consumes m sigs + 1 dummy from the stack.
            // Look back to find M (the OP_N that precedes the pubkeys).
            0xae | 0xaf => {
                // Find M by scanning backward for the OP_N before the pubkey pushes.
                // The M value was pushed before the pubkeys. We conservatively
                // look back in the script for the most recent OP_1..OP_16.
                let m = find_multisig_m(script_bytes, pos);
                // m sigs + 1 dummy byte (Bitcoin consensus bug)
                count += m + 1;
                pos += 1;
            }

            // Hash-lock patterns: OP_SHA256/HASH160/HASH256/RIPEMD160 followed by
            // a push (the expected hash) then OP_EQUAL/OP_EQUALVERIFY implies 1
            // preimage from the stack.
            0xa7..=0xaa => {
                // Look ahead past any data push to find EQUAL/EQUALVERIFY
                let next = skip_push(script_bytes, pos + 1);
                if next < len && (script_bytes[next] == 0x87 || script_bytes[next] == 0x88) {
                    count += 1;
                }
                pos += 1;
            }

            // All other opcodes
            _ => {
                pos += 1;
            }
        }
    }

    count
}

/// If `pos` points at a push opcode, return the position after the pushed data.
/// Otherwise return `pos` unchanged. Used to skip hash values in hash-lock patterns.
fn skip_push(script_bytes: &[u8], pos: usize) -> usize {
    let len = script_bytes.len();
    if pos >= len {
        return pos;
    }
    let opcode = script_bytes[pos];
    match opcode {
        // OP_PUSHBYTES_1..75
        0x01..=0x4b => pos + 1 + opcode as usize,
        // OP_PUSHDATA1
        0x4c if pos + 1 < len => pos + 2 + script_bytes[pos + 1] as usize,
        // OP_PUSHDATA2
        0x4d if pos + 2 < len => {
            let push_len =
                u16::from_le_bytes([script_bytes[pos + 1], script_bytes[pos + 2]]) as usize;
            pos + 3 + push_len
        }
        _ => pos,
    }
}

/// Scan backward from a CHECKMULTISIG to find the M value.
/// Returns the M value (number of required signatures), defaulting to 1.
fn find_multisig_m(script_bytes: &[u8], checkmultisig_pos: usize) -> usize {
    // Walk backward past the N pubkeys to find M.
    // The pattern is: OP_M <pubkey1> <pubkey2> ... OP_N OP_CHECKMULTISIG
    // OP_N is right before CHECKMULTISIG. OP_M is before all the pubkey pushes.
    if checkmultisig_pos == 0 {
        return 1;
    }

    // The byte before CHECKMULTISIG should be OP_N (0x51..0x60)
    let n_pos = checkmultisig_pos - 1;
    let n_byte = script_bytes[n_pos];
    if !(0x51..=0x60).contains(&n_byte) {
        return 1;
    }
    let n = (n_byte - 0x50) as usize;

    // Walk backward past N pubkey pushes (each is 0x21 + 33 bytes = 34 bytes)
    let pubkeys_size = n * 34; // OP_PUSHBYTES_33 + 33 bytes per key
    if n_pos < pubkeys_size + 1 {
        return 1;
    }

    let m_pos = n_pos - pubkeys_size - 1;
    // Verify all pubkey pushes are 0x21 (OP_PUSHBYTES_33)
    for i in 0..n {
        let push_pos = m_pos + 1 + i * 34;
        if push_pos >= script_bytes.len() || script_bytes[push_pos] != 0x21 {
            return 1;
        }
    }

    let m_byte = script_bytes[m_pos];
    if (0x51..=0x60).contains(&m_byte) {
        (m_byte - 0x50) as usize
    } else {
        1
    }
}

/// Compute the witness breakdown for a single input.
///
/// Quantifies essential vs dead witness bytes by:
/// 1. Stripping the script to its essential form (removing dead regions)
/// 2. Counting how many stack items the essential script consumes
/// 3. Comparing actual witness items against the essential count
///
/// Returns None for spend types that are inherently minimal (key-path, P2WPKH, legacy, empty).
pub(crate) fn compute_witness_breakdown(
    input: &TxIn,
    spend_type: &SpendType,
    dead_regions: &[DeadCodeRegion],
    _input_index: usize,
) -> Option<WitnessBreakdown> {
    match spend_type {
        SpendType::P2trScriptPath {
            tapscript,
            control_block,
        } => {
            let witness_items: Vec<&[u8]> = input.witness.iter().collect();
            let total_witness_bytes: usize = witness_items.iter().map(|i| i.len()).sum();

            let (essential_script, _bytes_removed) = strip_to_essential(tapscript, dead_regions);

            let control_block_bytes = control_block.len();
            let original_script_bytes = tapscript.len();
            let essential_script_bytes = essential_script.len();

            // Stack items = all witness items except the tapscript and control block
            // With annex: last item is annex, second-to-last is control block, third-to-last is script
            let has_annex = witness_items.len() >= 3
                && witness_items
                    .last()
                    .is_some_and(|a| a.first() == Some(&0x50) && a.len() > 1);

            let overhead_items = if has_annex { 3 } else { 2 }; // script + control_block [+ annex]
            let actual_stack_items = witness_items.len().saturating_sub(overhead_items);

            // Try taint-tracking simulator first; fall back to conservative counter
            let (essential_stack_items, essential_indices) =
                match simulate_essential_witnesses(actual_stack_items, &essential_script, true) {
                    Some(indices) => (indices.len(), Some(indices)),
                    None => (count_stack_consumption(&essential_script, true), None),
                };
            let excess_stack_items = actual_stack_items.saturating_sub(essential_stack_items);

            // Compute stack byte sizes — precise when simulator provides indices
            let (essential_stack_bytes, excess_stack_bytes) = compute_stack_bytes(
                &witness_items,
                actual_stack_items,
                &essential_indices,
                essential_stack_items,
            );

            let essential_bytes =
                essential_script_bytes + control_block_bytes + essential_stack_bytes;
            let dead_bytes = total_witness_bytes.saturating_sub(essential_bytes);

            Some(WitnessBreakdown {
                essential_bytes,
                dead_bytes,
                essential_script_bytes,
                original_script_bytes,
                control_block_bytes,
                essential_stack_items,
                actual_stack_items,
                excess_stack_items,
                excess_stack_bytes,
            })
        }

        SpendType::P2wsh { witness_script } => {
            let witness_items: Vec<&[u8]> = input.witness.iter().collect();
            let total_witness_bytes: usize = witness_items.iter().map(|i| i.len()).sum();

            let (essential_script, _bytes_removed) =
                strip_to_essential(witness_script, dead_regions);

            let original_script_bytes = witness_script.len();
            let essential_script_bytes = essential_script.len();

            // P2WSH: last witness item is the witness script, everything before is stack
            let actual_stack_items = witness_items.len().saturating_sub(1);

            // Try taint-tracking simulator first; fall back to conservative counter
            let (essential_stack_items, essential_indices) =
                match simulate_essential_witnesses(actual_stack_items, &essential_script, false) {
                    Some(indices) => (indices.len(), Some(indices)),
                    None => (count_stack_consumption(&essential_script, false), None),
                };
            let excess_stack_items = actual_stack_items.saturating_sub(essential_stack_items);

            let (essential_stack_bytes, excess_stack_bytes) = compute_stack_bytes(
                &witness_items,
                actual_stack_items,
                &essential_indices,
                essential_stack_items,
            );

            let essential_bytes = essential_script_bytes + essential_stack_bytes;
            let dead_bytes = total_witness_bytes.saturating_sub(essential_bytes);

            Some(WitnessBreakdown {
                essential_bytes,
                dead_bytes,
                essential_script_bytes,
                original_script_bytes,
                control_block_bytes: 0,
                essential_stack_items,
                actual_stack_items,
                excess_stack_items,
                excess_stack_bytes,
            })
        }

        // Key-path, P2WPKH, Legacy, Empty — inherently minimal, no breakdown needed
        _ => None,
    }
}

/// Compute essential and excess stack byte sizes.
///
/// When the simulator provides precise essential indices, sum bytes of those
/// specific witness items. Otherwise, fall back to the positional heuristic
/// (first N items are essential).
fn compute_stack_bytes(
    witness_items: &[&[u8]],
    actual_stack_items: usize,
    essential_indices: &Option<BTreeSet<u16>>,
    essential_stack_items: usize,
) -> (usize, usize) {
    let stack_items = &witness_items[..actual_stack_items.min(witness_items.len())];

    if let Some(indices) = essential_indices {
        let mut essential_bytes = 0usize;
        let mut excess_bytes = 0usize;
        for (idx, item) in stack_items.iter().enumerate() {
            if indices.contains(&(idx as u16)) {
                essential_bytes += item.len();
            } else {
                excess_bytes += item.len();
            }
        }
        (essential_bytes, excess_bytes)
    } else {
        // Positional fallback: first `essential_stack_items` are essential
        let essential_bytes: usize = stack_items
            .iter()
            .take(essential_stack_items)
            .map(|i| i.len())
            .sum();
        let excess_bytes: usize = stack_items
            .iter()
            .skip(essential_stack_items)
            .map(|i| i.len())
            .sum();
        (essential_bytes, excess_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_to_essential_no_regions() {
        let script = vec![0xac]; // OP_CHECKSIG
        let (essential, removed) = strip_to_essential(&script, &[]);
        assert_eq!(essential, script);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_strip_to_essential_removes_region() {
        // Script: [OP_FALSE(0x00), OP_IF(0x63), 0x03, 'o', 'r', 'd', OP_ENDIF(0x68), OP_CHECKSIG(0xac)]
        let script = vec![0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0xac];
        let region = DeadCodeRegion {
            location: crate::verdict::AnalysisLocation::Input(0),
            dead_code_type: crate::verdict::DeadCodeType::InscriptionEnvelope,
            offset: 0,
            size: 7, // OP_FALSE through OP_ENDIF
            description: String::new(),
        };
        let (essential, removed) = strip_to_essential(&script, &[region]);
        assert_eq!(essential, vec![0xac]); // Only OP_CHECKSIG remains
        assert_eq!(removed, 7);
    }

    #[test]
    fn test_count_stack_consumption_checksig() {
        // OP_CHECKSIG
        let script = vec![0xac];
        assert_eq!(count_stack_consumption(&script, true), 1);
        assert_eq!(count_stack_consumption(&script, false), 1);
    }

    #[test]
    fn test_count_stack_consumption_checksigadd() {
        // OP_CHECKSIGADD (tapscript only)
        let script = vec![0xba];
        assert_eq!(count_stack_consumption(&script, true), 1);
        // Non-tapscript: OP_CHECKSIGADD not counted
        assert_eq!(count_stack_consumption(&script, false), 0);
    }

    #[test]
    fn test_count_stack_consumption_multisig() {
        // 2-of-3 multisig: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        let mut script = vec![0x52]; // OP_2
        for _ in 0..3 {
            script.push(0x21); // OP_PUSHBYTES_33
            script.extend([0xAA; 33]);
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG
                           // Should consume 2 sigs + 1 dummy = 3
        assert_eq!(count_stack_consumption(&script, false), 3);
    }

    #[test]
    fn test_count_stack_consumption_hashlock() {
        // OP_SHA256 OP_EQUALVERIFY OP_CHECKSIG
        let script = vec![0xa8, 0x88, 0xac];
        // 1 preimage + 1 sig = 2
        assert_eq!(count_stack_consumption(&script, false), 2);
    }

    #[test]
    fn test_find_multisig_m_basic() {
        // 2-of-3: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        let mut script = vec![0x52]; // OP_2
        for _ in 0..3 {
            script.push(0x21);
            script.extend([0xAA; 33]);
        }
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG
        let checkmultisig_pos = script.len() - 1;
        assert_eq!(find_multisig_m(&script, checkmultisig_pos), 2);
    }
}
