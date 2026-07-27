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
//| FILE: payout_validator.rs                                                                                            |
//|======================================================================================================================|

//! Payout proposal validation
//!
//! Multi-layer validation to prevent fund theft through malformed
//! or malicious payout proposals. All arithmetic uses checked operations.

use std::collections::HashSet;
use thiserror::Error;
use tracing::warn;

use ghost_common::types::PayoutProposal;

/// Dust threshold in satoshis (Bitcoin Core default)
pub const DUST_THRESHOLD: u64 = 546;

/// Maximum Bitcoin supply in satoshis (21 million BTC)
pub const MAX_SUPPLY_SATS: u64 = 21_000_000 * 100_000_000;

/// Maximum block reward (subsidy + fees) we'd ever expect
/// This is a sanity check - early blocks had 50 BTC subsidy
pub const MAX_BLOCK_REWARD_SATS: u64 = 100 * 100_000_000; // 100 BTC

/// Maximum number of payout outputs
///
/// Sized for: up to 1000 miner outputs + ~100 node reward outputs +
/// treasury + finder bonus + coinbase-flags witness. At ~44 bytes per
/// P2TR output that's ~50 KB or ~1.25% of the 4M-WU block weight —
/// comfortably below where it would crowd out fee-paying transactions.
pub const MAX_PAYOUT_OUTPUTS: usize = 1200;

/// Payout validation errors
#[derive(Debug, Error)]
pub enum PayoutValidationError {
    #[error("Arithmetic overflow in {0}")]
    Overflow(&'static str),

    #[error("Total distributed ({distributed} sats) exceeds available ({available} sats)")]
    ExceedsAvailable { distributed: u64, available: u64 },

    #[error("Block reward ({0} sats) exceeds maximum expected ({MAX_BLOCK_REWARD_SATS} sats)")]
    UnreasonableReward(u64),

    #[error("Payout amount ({0} sats) exceeds maximum supply")]
    ExceedsSupply(u64),

    #[error("Dust output: {0} sats is below threshold of {DUST_THRESHOLD} sats")]
    DustOutput(u64),

    #[error("Empty payout address for recipient")]
    EmptyAddress,

    #[error("Invalid output script: {0}")]
    InvalidScript(String),

    #[error("Duplicate recipient: {0}")]
    DuplicateRecipient(String),

    #[error("Too many outputs: {0} (max {MAX_PAYOUT_OUTPUTS})")]
    TooManyOutputs(usize),

    #[error("No miner payouts in proposal")]
    NoMinerPayouts,

    #[error("Proposal timestamp in future: {0}")]
    FutureTimestamp(u64),

    #[error("Proposal timestamp too old: {0}")]
    StaleTimestamp(u64),

    #[error("Round ID mismatch: proposal has {proposal}, expected {expected}")]
    RoundMismatch { proposal: u64, expected: u64 },

    #[error("Block hash mismatch")]
    BlockHashMismatch,

    #[error("Negative payout detected")]
    NegativeAmount,

    #[error("M-09: Underpayment detected: distributing {distributed} sats but {available} available (minimum 90% = {minimum})")]
    Underpayment {
        distributed: u64,
        available: u64,
        minimum: u64,
    },
}

/// Block data for validation context
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// Block subsidy in satoshis
    pub subsidy: u64,
    /// Transaction fees in satoshis
    pub fees: u64,
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: [u8; 32],
    /// Current round ID
    pub round_id: u64,
    /// Current timestamp
    pub current_time: u64,
}

/// Validate a payout proposal thoroughly
pub fn validate_payout_proposal(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // 1. Basic sanity checks
    validate_basic_sanity(proposal, context)?;

    // 2. Validate amounts don't overflow and sum correctly
    validate_amounts(proposal, context)?;

    // 3. Validate all addresses
    validate_addresses(proposal)?;

    // 4. Check for duplicates
    validate_no_duplicates(proposal)?;

    // 5. Validate timestamps
    validate_timestamps(proposal, context)?;

    Ok(())
}

/// Basic sanity checks
fn validate_basic_sanity(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // Must have miner payouts
    if proposal.miner_payouts.is_empty() {
        return Err(PayoutValidationError::NoMinerPayouts);
    }

    // Output count limit
    let total_outputs = proposal.miner_payouts.len() + proposal.node_payouts.len();
    if total_outputs > MAX_PAYOUT_OUTPUTS {
        return Err(PayoutValidationError::TooManyOutputs(total_outputs));
    }

    // Round ID must match
    if proposal.round_id != context.round_id {
        return Err(PayoutValidationError::RoundMismatch {
            proposal: proposal.round_id,
            expected: context.round_id,
        });
    }

    // Block hash must match
    if proposal.block_hash != context.block_hash {
        return Err(PayoutValidationError::BlockHashMismatch);
    }

    // Subsidy and fees must match
    let claimed_total = proposal
        .subsidy
        .checked_add(proposal.tx_fees)
        .ok_or(PayoutValidationError::Overflow("claimed total"))?;

    let actual_total = context
        .subsidy
        .checked_add(context.fees)
        .ok_or(PayoutValidationError::Overflow("actual total"))?;

    // Allow small discrepancy due to fee estimation
    if claimed_total > actual_total {
        return Err(PayoutValidationError::ExceedsAvailable {
            distributed: claimed_total,
            available: actual_total,
        });
    }

    // M-09: Detect underpayment — distributing less than 90% of available is suspicious
    let minimum_distribution = actual_total * 90 / 100;
    if claimed_total < minimum_distribution {
        return Err(PayoutValidationError::Underpayment {
            distributed: claimed_total,
            available: actual_total,
            minimum: minimum_distribution,
        });
    }

    // Sanity check on block reward
    if actual_total > MAX_BLOCK_REWARD_SATS {
        warn!(
            actual = actual_total,
            max = MAX_BLOCK_REWARD_SATS,
            "Unusually large block reward"
        );
        return Err(PayoutValidationError::UnreasonableReward(actual_total));
    }

    Ok(())
}

/// Validate all amounts using checked arithmetic
fn validate_amounts(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // Calculate available funds
    let available = context
        .subsidy
        .checked_add(context.fees)
        .ok_or(PayoutValidationError::Overflow("available funds"))?;

    // Sum miner payouts with overflow checking
    let mut miner_total: u64 = 0;
    for payout in &proposal.miner_payouts {
        // Check individual amount
        if payout.amount > MAX_SUPPLY_SATS {
            return Err(PayoutValidationError::ExceedsSupply(payout.amount));
        }

        // Check for dust (unless zero, which will be filtered)
        if payout.amount > 0 && payout.amount < DUST_THRESHOLD {
            return Err(PayoutValidationError::DustOutput(payout.amount));
        }

        miner_total = miner_total
            .checked_add(payout.amount)
            .ok_or(PayoutValidationError::Overflow("miner payouts sum"))?;
    }

    // Sum node payouts with overflow checking
    let mut node_total: u64 = 0;
    for payout in &proposal.node_payouts {
        if payout.amount > MAX_SUPPLY_SATS {
            return Err(PayoutValidationError::ExceedsSupply(payout.amount));
        }

        if payout.amount > 0 && payout.amount < DUST_THRESHOLD {
            return Err(PayoutValidationError::DustOutput(payout.amount));
        }

        node_total = node_total
            .checked_add(payout.amount)
            .ok_or(PayoutValidationError::Overflow("node payouts sum"))?;
    }

    // Total distributed
    let total_distributed = miner_total
        .checked_add(node_total)
        .ok_or(PayoutValidationError::Overflow("miner + node sum"))?
        .checked_add(proposal.treasury_amount)
        .ok_or(PayoutValidationError::Overflow("total distribution"))?;

    // Must not exceed available
    if total_distributed > available {
        return Err(PayoutValidationError::ExceedsAvailable {
            distributed: total_distributed,
            available,
        });
    }

    Ok(())
}

/// Validate all output addresses/scripts
fn validate_addresses(proposal: &PayoutProposal) -> Result<(), PayoutValidationError> {
    for payout in proposal
        .miner_payouts
        .iter()
        .chain(proposal.node_payouts.iter())
    {
        // Skip zero-amount payouts
        if payout.amount == 0 {
            continue;
        }

        // Address must not be empty
        if payout.address.is_empty() {
            return Err(PayoutValidationError::EmptyAddress);
        }

        // Validate script format
        validate_output_script(&payout.address)?;
    }

    Ok(())
}

/// Validate a Bitcoin output script (scriptPubKey)
///
/// HIGH-10: Uses bounds-checked access patterns for all script validation
fn validate_output_script(script: &[u8]) -> Result<(), PayoutValidationError> {
    // Helper to safely get a byte at an index
    let get = |idx: usize| script.get(idx).copied();

    // Standard script types and their expected lengths
    let is_valid = match script.len() {
        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        25 => {
            get(0) == Some(0x76)
                && get(1) == Some(0xa9)
                && get(2) == Some(0x14)
                && get(23) == Some(0x88)
                && get(24) == Some(0xac)
        }

        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        23 => get(0) == Some(0xa9) && get(1) == Some(0x14) && get(22) == Some(0x87),

        // P2WPKH: OP_0 <20 bytes>
        22 => get(0) == Some(0x00) && get(1) == Some(0x14),

        // P2WSH: OP_0 <32 bytes>
        // This covers both standard P2WSH and multi-sig P2WSH
        // P2TR: OP_1 <32 bytes>
        34 => {
            (get(0) == Some(0x00) && get(1) == Some(0x20))
                || (get(0) == Some(0x51) && get(1) == Some(0x20))
        }

        // Unknown length
        _ => false,
    };

    if is_valid {
        Ok(())
    } else {
        let hex = hex::encode(script);
        let preview = if hex.len() > 40 {
            format!("{}...", &hex[..40])
        } else {
            hex
        };
        Err(PayoutValidationError::InvalidScript(preview))
    }
}

/// Validate a multi-sig witness script (redeem script)
///
/// Multi-sig scripts have the format:
/// `OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG`
///
/// Where:
/// - OP_M (0x51-0x60) represents M (1-16)
/// - Each pubkey is 33 bytes (compressed) or 65 bytes (uncompressed)
/// - OP_N (0x51-0x60) represents N (1-16)
/// - OP_CHECKMULTISIG (0xae)
pub fn validate_multisig_witness_script(
    script: &[u8],
    expected_m: u8,
    expected_n: u8,
) -> Result<(), PayoutValidationError> {
    // HIGH-6: Validate expected_n is within valid multi-sig bounds BEFORE multiplication
    // This prevents overflow in the minimum length calculation below
    if expected_n > 15 {
        return Err(PayoutValidationError::InvalidScript(format!(
            "HIGH-6: invalid N value: {} (maximum is 15 for standard multi-sig)",
            expected_n
        )));
    }
    if expected_m > expected_n || expected_m == 0 {
        return Err(PayoutValidationError::InvalidScript(format!(
            "HIGH-6: invalid M-of-N: {}-of-{} (M must be 1-N, N must be 1-15)",
            expected_m, expected_n
        )));
    }

    // Minimum length: OP_M + N pubkeys + OP_N + OP_CHECKMULTISIG
    // For compressed pubkeys: 1 + (33+1)*N + 1 + 1 = 3 + 34*N
    // HIGH-6: safe since expected_n <= 15, so 34 * 15 = 510 fits in usize
    if script.len() < 3 + (34 * expected_n as usize) {
        return Err(PayoutValidationError::InvalidScript(
            "multi-sig script too short".into(),
        ));
    }

    // HIGH-6: Use .get() for bounds-checked access instead of direct indexing
    // Check OP_M (0x51 = OP_1, 0x52 = OP_2, etc.)
    let m_opcode = *script.first().ok_or_else(|| {
        PayoutValidationError::InvalidScript("HIGH-6: script too short for OP_M".into())
    })?;
    if !(0x51..=0x60).contains(&m_opcode) {
        return Err(PayoutValidationError::InvalidScript(
            "invalid OP_M in multi-sig script".into(),
        ));
    }
    let actual_m = m_opcode - 0x50;

    if actual_m != expected_m {
        return Err(PayoutValidationError::InvalidScript(format!(
            "M mismatch: script has {}, expected {}",
            actual_m, expected_m
        )));
    }

    // Count pubkeys and find OP_N
    let mut pos = 1;
    let mut pubkey_count = 0;

    // HIGH-6: Prevent underflow by checking pos + 2 < len instead of pos < len - 2
    while pos + 2 < script.len() {
        // HIGH-6: Use .get() for bounds-checked access
        let len = *script.get(pos).ok_or_else(|| {
            PayoutValidationError::InvalidScript(format!(
                "HIGH-6: script truncated at position {}",
                pos
            ))
        })? as usize;
        if len == 33 || len == 65 {
            // Valid pubkey length (compressed or uncompressed)
            pos += 1 + len;
            pubkey_count += 1;
        } else if (0x51..=0x60).contains(&len) {
            // This is OP_N
            break;
        } else {
            return Err(PayoutValidationError::InvalidScript(format!(
                "unexpected opcode 0x{:02x} at position {}",
                len, pos
            )));
        }
    }

    if pubkey_count != expected_n {
        return Err(PayoutValidationError::InvalidScript(format!(
            "N mismatch: script has {} pubkeys, expected {}",
            pubkey_count, expected_n
        )));
    }

    // Check OP_N
    // HIGH-6: Use checked access to prevent out-of-bounds
    if pos + 1 >= script.len() {
        return Err(PayoutValidationError::InvalidScript(
            "multi-sig script truncated before OP_N".into(),
        ));
    }

    // HIGH-6: Use .get() for bounds-checked access
    let n_opcode = *script.get(pos).ok_or_else(|| {
        PayoutValidationError::InvalidScript("HIGH-6: script truncated at OP_N position".into())
    })?;
    if !(0x51..=0x60).contains(&n_opcode) {
        return Err(PayoutValidationError::InvalidScript(
            "invalid OP_N in multi-sig script".into(),
        ));
    }
    let actual_n = n_opcode - 0x50;

    if actual_n != expected_n {
        return Err(PayoutValidationError::InvalidScript(format!(
            "N opcode mismatch: script has {}, expected {}",
            actual_n, expected_n
        )));
    }

    // Check OP_CHECKMULTISIG
    pos += 1;
    if pos >= script.len() {
        return Err(PayoutValidationError::InvalidScript(
            "multi-sig script truncated before OP_CHECKMULTISIG".into(),
        ));
    }

    // HIGH-6: Use .get() for bounds-checked access
    let checkmultisig_opcode = *script.get(pos).ok_or_else(|| {
        PayoutValidationError::InvalidScript(
            "HIGH-6: script truncated at OP_CHECKMULTISIG position".into(),
        )
    })?;

    if checkmultisig_opcode != 0xae {
        return Err(PayoutValidationError::InvalidScript(format!(
            "expected OP_CHECKMULTISIG (0xae), got 0x{:02x}",
            checkmultisig_opcode
        )));
    }

    // Note: M <= N validation is done at the start of the function (HIGH-6)

    Ok(())
}

/// Check for duplicate recipients
fn validate_no_duplicates(proposal: &PayoutProposal) -> Result<(), PayoutValidationError> {
    let mut seen = HashSet::new();

    for payout in proposal
        .miner_payouts
        .iter()
        .chain(proposal.node_payouts.iter())
    {
        // Skip zero amounts
        if payout.amount == 0 {
            continue;
        }

        if !seen.insert(&payout.recipient_id) {
            let id_hex = hex::encode(&payout.recipient_id[..8]);
            return Err(PayoutValidationError::DuplicateRecipient(id_hex));
        }
    }

    Ok(())
}

/// Validate proposal timestamps
fn validate_timestamps(
    proposal: &PayoutProposal,
    context: &BlockContext,
) -> Result<(), PayoutValidationError> {
    // Not too far in future (5 minutes)
    // L-13: Use checked_add to prevent overflow on timestamp arithmetic
    const MAX_FUTURE_SECS: u64 = 300;
    let max_allowed_time = context.current_time.checked_add(MAX_FUTURE_SECS).ok_or(
        PayoutValidationError::Overflow("L-13: future timestamp calculation"),
    )?;
    if proposal.timestamp > max_allowed_time {
        return Err(PayoutValidationError::FutureTimestamp(proposal.timestamp));
    }

    // Not too old (1 hour)
    // L-13: Use checked_add to prevent overflow on timestamp arithmetic
    const MAX_AGE_SECS: u64 = 3600;
    let min_allowed_time =
        proposal
            .timestamp
            .checked_add(MAX_AGE_SECS)
            .ok_or(PayoutValidationError::Overflow(
                "L-13: stale timestamp calculation",
            ))?;
    if min_allowed_time < context.current_time {
        return Err(PayoutValidationError::StaleTimestamp(proposal.timestamp));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::{PayoutEntry, PayoutType};

    fn test_context() -> BlockContext {
        BlockContext {
            subsidy: 625_000_000, // 6.25 BTC
            fees: 10_000_000,     // 0.1 BTC
            height: 800_000,
            block_hash: [1u8; 32],
            round_id: 1,
            current_time: 1700000000,
        }
    }

    fn valid_p2wpkh_script() -> Vec<u8> {
        let mut script = vec![0x00, 0x14]; // OP_0 <20 bytes>
        script.extend_from_slice(&[0u8; 20]);
        script
    }

    fn test_payout(amount: u64) -> PayoutEntry {
        PayoutEntry {
            address: valid_p2wpkh_script(),
            amount,
            recipient_id: [1u8; 32],
            payout_type: PayoutType::Mining,
        }
    }

    fn valid_proposal() -> PayoutProposal {
        PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 1,
            block_hash: [1u8; 32],
            block_height: 800_000,
            proposer: [0u8; 32],
            miner_payouts: vec![test_payout(300_000_000)],
            node_payouts: vec![],
            treasury_amount: 6_350_000,                 // ~1%
            treasury_address: b"bc1qtreasury".to_vec(), // H-MINE-3: snapshot address
            tx_fees: 10_000_000,
            subsidy: 625_000_000,
            timestamp: 1700000000,
            tx_fees_unallocated: 0,
        }
    }

    #[test]
    fn test_valid_proposal() {
        let proposal = valid_proposal();
        let context = test_context();
        assert!(validate_payout_proposal(&proposal, &context).is_ok());
    }

    #[test]
    fn test_exceeds_available() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts[0].amount = 700_000_000; // More than available
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(
            result,
            Err(PayoutValidationError::ExceedsAvailable { .. })
        ));
    }

    #[test]
    fn test_dust_output() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts.push(test_payout(100)); // Dust
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::DustOutput(_))));
    }

    #[test]
    fn test_empty_address() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts[0].address = vec![]; // Empty
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(result, Err(PayoutValidationError::EmptyAddress)));
    }

    #[test]
    fn test_invalid_script() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts[0].address = vec![0x01, 0x02, 0x03]; // Invalid
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(
            result,
            Err(PayoutValidationError::InvalidScript(_))
        ));
    }

    #[test]
    fn test_duplicate_recipient() {
        let mut proposal = valid_proposal();
        proposal.miner_payouts.push(test_payout(100_000_000)); // Same recipient_id
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(
            result,
            Err(PayoutValidationError::DuplicateRecipient(_))
        ));
    }

    #[test]
    fn test_too_many_outputs() {
        let mut proposal = valid_proposal();
        for i in 0..MAX_PAYOUT_OUTPUTS + 1 {
            let mut payout = test_payout(1000);
            payout.recipient_id = [i as u8; 32];
            proposal.miner_payouts.push(payout);
        }
        let context = test_context();

        let result = validate_payout_proposal(&proposal, &context);
        assert!(matches!(
            result,
            Err(PayoutValidationError::TooManyOutputs(_))
        ));
    }

    #[test]
    fn test_valid_scripts() {
        // P2PKH
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0u8; 20]);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        assert!(validate_output_script(&p2pkh).is_ok());

        // P2SH
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&[0u8; 20]);
        p2sh.push(0x87);
        assert!(validate_output_script(&p2sh).is_ok());

        // P2WPKH
        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[0u8; 20]);
        assert!(validate_output_script(&p2wpkh).is_ok());

        // P2TR
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0u8; 32]);
        assert!(validate_output_script(&p2tr).is_ok());

        // P2WSH (multi-sig compatible)
        let mut p2wsh = vec![0x00, 0x20];
        p2wsh.extend_from_slice(&[0u8; 32]);
        assert!(validate_output_script(&p2wsh).is_ok());
    }

    #[test]
    fn test_multisig_witness_script_2of3() {
        // Build a 2-of-3 multi-sig witness script
        // OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG
        let mut script = vec![0x52]; // OP_2

        // Add 3 compressed pubkeys (33 bytes each)
        for _ in 0..3 {
            script.push(33); // push 33 bytes
            script.extend_from_slice(&[0x02; 33]); // fake compressed pubkey
        }

        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        assert!(validate_multisig_witness_script(&script, 2, 3).is_ok());
    }

    #[test]
    fn test_multisig_witness_script_invalid_m() {
        // Build script with wrong M
        let mut script = vec![0x53]; // OP_3 (but we expect 2)

        for _ in 0..3 {
            script.push(33);
            script.extend_from_slice(&[0x02; 33]);
        }

        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        let result = validate_multisig_witness_script(&script, 2, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_multisig_witness_script_wrong_pubkey_count() {
        // Build 2-of-3 script but only include 2 pubkeys
        let mut script = vec![0x52]; // OP_2

        for _ in 0..2 {
            script.push(33);
            script.extend_from_slice(&[0x02; 33]);
        }

        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG

        let result = validate_multisig_witness_script(&script, 2, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_multisig_witness_script_missing_checkmultisig() {
        let mut script = vec![0x52]; // OP_2

        for _ in 0..3 {
            script.push(33);
            script.extend_from_slice(&[0x02; 33]);
        }

        script.push(0x53); // OP_3
                           // Missing OP_CHECKMULTISIG

        let result = validate_multisig_witness_script(&script, 2, 3);
        assert!(result.is_err());
    }
}
