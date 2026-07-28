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
//| FILE: witness.rs                                                                                                     |
//|======================================================================================================================|

use bitcoin::TxIn;

#[derive(Debug, Clone)]
pub enum SpendType {
    P2trKeyPath,
    P2trScriptPath {
        tapscript: Vec<u8>,
        control_block: Vec<u8>,
    },
    P2wsh {
        witness_script: Vec<u8>,
    },
    P2wpkh,
    Legacy,
    Empty,
}

impl std::fmt::Display for SpendType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P2trKeyPath => write!(f, "P2TR-keypath"),
            Self::P2trScriptPath { .. } => write!(f, "P2TR-scriptpath"),
            Self::P2wsh { .. } => write!(f, "P2WSH"),
            Self::P2wpkh => write!(f, "P2WPKH"),
            Self::Legacy => write!(f, "Legacy"),
            Self::Empty => write!(f, "Empty"),
        }
    }
}

/// Identify the spend type from a transaction input's witness data.
pub(crate) fn identify_spend(input: &TxIn) -> SpendType {
    let witness = &input.witness;
    let items: Vec<&[u8]> = witness.iter().collect();

    match items.len() {
        0 => {
            if input.script_sig.is_empty() {
                SpendType::Empty
            } else {
                SpendType::Legacy
            }
        }
        1 => {
            // Single element of 64 or 65 bytes = Schnorr signature (key path)
            let sig = items[0];
            if sig.len() == 64 || sig.len() == 65 {
                SpendType::P2trKeyPath
            } else {
                // Unusual single-element witness, treat as legacy
                SpendType::Legacy
            }
        }
        2 => {
            // Check for annex (shouldn't appear with 2 items, but be safe)
            // P2WPKH: [signature, pubkey(33 bytes)]
            let second = items[1];
            if second.len() == 33 && (second[0] == 0x02 || second[0] == 0x03) {
                SpendType::P2wpkh
            } else {
                // Could be P2WSH with no additional witness data
                SpendType::P2wsh {
                    witness_script: second.to_vec(),
                }
            }
        }
        n => {
            // 3+ items: check if last is a control block (P2TR script path)
            // With annex: second-to-last is control block, last starts with 0x50
            let (potential_cb_idx, has_annex) =
                if items[n - 1].first() == Some(&0x50) && items[n - 1].len() > 1 && n >= 3 {
                    (n - 2, true)
                } else {
                    (n - 1, false)
                };

            let potential_cb = items[potential_cb_idx];
            if is_control_block(potential_cb) {
                let script_idx = potential_cb_idx - 1;
                SpendType::P2trScriptPath {
                    tapscript: items[script_idx].to_vec(),
                    control_block: potential_cb.to_vec(),
                }
            } else if has_annex {
                // Has annex but no control block → P2WSH with annex (unusual)
                SpendType::P2wsh {
                    witness_script: items[n - 2].to_vec(),
                }
            } else {
                // Last element is witness script for P2WSH
                SpendType::P2wsh {
                    witness_script: items[n - 1].to_vec(),
                }
            }
        }
    }
}

/// Check if a witness element is a taproot annex (starts with 0x50).
pub(crate) fn has_annex(input: &TxIn) -> bool {
    let witness = &input.witness;
    let items: Vec<&[u8]> = witness.iter().collect();
    if items.len() >= 2 {
        if let Some(&first_byte) = items.last().and_then(|item| item.first()) {
            // Annex starts with 0x50 and witness must have 3+ elements for script-path
            // (or 2+ elements in ambiguous cases). The annex is the last element.
            // But we only flag it as annex if it starts with 0x50 and there are
            // enough items for it not to be the script/signature itself.
            return first_byte == 0x50 && items.last().is_some_and(|a| a.len() > 1);
        }
    }
    false
}

/// Check if data is a valid taproot control block.
/// Length must be 33 + 32*k (for k >= 0), first byte >= 0xc0.
pub(crate) fn is_control_block(data: &[u8]) -> bool {
    if data.len() < 33 {
        return false;
    }
    if data[0] < 0xc0 {
        return false;
    }
    // Length = 33 + 32*k → (len - 33) must be divisible by 32
    (data.len() - 33).is_multiple_of(32)
}
