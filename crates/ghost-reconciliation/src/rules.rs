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
//| FILE: rules.rs                                                                                                       |
//|======================================================================================================================|

//! Settlement rules and validation

use crate::error::{ReconciliationError, ReconciliationResult};
use crate::{DISPUTE_WINDOW_BLOCKS, MIN_SETTLEMENT_SATS};

/// Validate a settlement request
pub fn validate_settlement(
    source_ghost_id: &str,
    destination_address: &str,
    amount_sats: u64,
) -> ReconciliationResult<()> {
    // Check minimum amount
    if amount_sats < MIN_SETTLEMENT_SATS {
        return Err(ReconciliationError::BelowMinimum {
            amount: amount_sats,
            minimum: MIN_SETTLEMENT_SATS,
        });
    }

    // Validate source ghost ID format
    if !source_ghost_id.starts_with("ghost1") {
        return Err(ReconciliationError::InvalidProof {
            reason: "Invalid source ghost ID format".to_string(),
        });
    }

    // Validate destination address (basic check)
    if destination_address.is_empty() {
        return Err(ReconciliationError::InvalidProof {
            reason: "Empty destination address".to_string(),
        });
    }

    // H-8: Reject legacy P2PKH addresses (1...) and P2SH addresses (3...)
    // Only SegWit (bc1q/tb1q/bcrt1q) addresses are accepted for settlement outputs.
    // Legacy addresses have larger witness discount costs and weaker security properties.
    if destination_address.starts_with('1') {
        return Err(ReconciliationError::InvalidProof {
            reason: "H-8: P2PKH addresses (1...) are not accepted. Use a SegWit address (bc1q...)"
                .to_string(),
        });
    }
    if destination_address.starts_with('3') {
        return Err(ReconciliationError::InvalidProof {
            reason: "H-8: P2SH addresses (3...) are not accepted. Use a SegWit address (bc1q...)"
                .to_string(),
        });
    }
    // Testnet legacy addresses
    if destination_address.starts_with('m')
        || destination_address.starts_with('n')
        || destination_address.starts_with('2')
    {
        return Err(ReconciliationError::InvalidProof {
            reason:
                "H-8: Legacy testnet addresses are not accepted. Use a SegWit address (tb1q...)"
                    .to_string(),
        });
    }

    // QUANTUM SAFETY: Reject P2TR addresses (bc1p...)
    // P2TR exposes public keys on-chain, making them vulnerable to quantum attacks
    if destination_address.starts_with("bc1p")
        || destination_address.starts_with("tb1p")
        || destination_address.starts_with("bcrt1p")
    {
        return Err(ReconciliationError::QuantumUnsafe);
    }

    // Check Bitcoin address prefix: only SegWit (bc1q/tb1q/bcrt1q) accepted
    let valid_prefix = destination_address.starts_with("bc1q")
        || destination_address.starts_with("tb1q")
        || destination_address.starts_with("bcrt1q");

    if !valid_prefix {
        return Err(ReconciliationError::InvalidProof {
            reason: "Invalid Bitcoin address prefix — only SegWit (bc1q/tb1q/bcrt1q) accepted"
                .to_string(),
        });
    }

    Ok(())
}

/// Check if dispute window has passed
pub fn is_dispute_window_passed(confirmation_height: u32, current_height: u32) -> bool {
    current_height >= confirmation_height + DISPUTE_WINDOW_BLOCKS
}

/// Get remaining dispute blocks
pub fn remaining_dispute_blocks(confirmation_height: u32, current_height: u32) -> u32 {
    let deadline = confirmation_height + DISPUTE_WINDOW_BLOCKS;
    deadline.saturating_sub(current_height)
}

/// Batch formation rules
#[derive(Debug)]
pub struct BatchRules {
    /// Minimum settlements per batch
    pub min_settlements: usize,
    /// Maximum settlements per batch
    pub max_settlements: usize,
    /// Batch timeout in seconds
    pub timeout_secs: u64,
    /// Force batch threshold (pending sats)
    pub force_batch_threshold_sats: u64,
}

impl Default for BatchRules {
    fn default() -> Self {
        Self {
            min_settlements: crate::MIN_BATCH_SIZE,
            max_settlements: crate::MAX_BATCH_SIZE,
            timeout_secs: crate::BATCH_TIMEOUT_SECS,
            force_batch_threshold_sats: 10_000_000_000, // 100 BTC
        }
    }
}

impl BatchRules {
    /// Check if batch should be formed
    pub fn should_form_batch(
        &self,
        pending_count: usize,
        pending_total_sats: u64,
        oldest_pending_age_secs: u64,
    ) -> bool {
        // Form if we have enough settlements
        if pending_count >= self.min_settlements {
            return true;
        }

        // Form if timeout reached and we have any pending
        if pending_count > 0 && oldest_pending_age_secs >= self.timeout_secs {
            return true;
        }

        // Form if total pending exceeds threshold
        if pending_total_sats >= self.force_batch_threshold_sats {
            return true;
        }

        false
    }

    /// Calculate priority score for batch formation
    pub fn batch_priority(&self, pending_count: usize, pending_total_sats: u64) -> f64 {
        let count_factor = pending_count as f64 / self.max_settlements as f64;
        let value_factor = pending_total_sats as f64 / self.force_batch_threshold_sats as f64;

        (count_factor * 0.4 + value_factor * 0.6).min(1.0)
    }
}

/// Dispute rules
pub struct DisputeRules {
    /// Dispute window in blocks
    pub window_blocks: u32,
    /// Minimum bond for dispute (satoshis)
    pub min_bond_sats: u64,
    /// Evidence submission deadline (blocks after dispute)
    pub evidence_deadline_blocks: u32,
}

impl Default for DisputeRules {
    fn default() -> Self {
        Self {
            window_blocks: DISPUTE_WINDOW_BLOCKS,
            min_bond_sats: 100_000,       // 0.001 BTC
            evidence_deadline_blocks: 36, // ~6 hours
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_settlement() {
        // Valid settlement
        assert!(validate_settlement("ghost1abc", "bc1qtest", 100_000).is_ok());

        // Below minimum
        assert!(validate_settlement("ghost1abc", "bc1qtest", 1_000).is_err());

        // Invalid ghost ID
        assert!(validate_settlement("invalid", "bc1qtest", 100_000).is_err());

        // Empty address
        assert!(validate_settlement("ghost1abc", "", 100_000).is_err());
    }

    #[test]
    fn test_validate_settlement_rejects_p2tr() {
        // QUANTUM SAFETY: P2TR addresses must be rejected

        // Mainnet P2TR
        let result = validate_settlement(
            "ghost1abc",
            "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297",
            100_000,
        );
        assert!(matches!(result, Err(ReconciliationError::QuantumUnsafe)));

        // Testnet P2TR
        let result = validate_settlement(
            "ghost1abc",
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            100_000,
        );
        assert!(matches!(result, Err(ReconciliationError::QuantumUnsafe)));

        // Regtest P2TR
        let result = validate_settlement("ghost1abc", "bcrt1ptest", 100_000);
        assert!(matches!(result, Err(ReconciliationError::QuantumUnsafe)));

        // P2WPKH should still work
        assert!(validate_settlement("ghost1abc", "bc1qtest", 100_000).is_ok());
    }

    #[test]
    fn test_dispute_window() {
        assert!(!is_dispute_window_passed(800_000, 800_100));
        assert!(is_dispute_window_passed(800_000, 800_144));
        assert!(is_dispute_window_passed(800_000, 800_200));

        assert_eq!(remaining_dispute_blocks(800_000, 800_100), 44);
        assert_eq!(remaining_dispute_blocks(800_000, 800_200), 0);
    }

    #[test]
    fn test_batch_rules() {
        let rules = BatchRules::default();

        // GHOST-12: MIN_BATCH_SIZE is now 10 (anonymity floor). >= 10 forms;
        // a single low-value settlement does NOT (would reveal its participant).
        assert!(rules.should_form_batch(10, 1_000_000, 0));
        assert!(!rules.should_form_batch(1, 1_000_000, 0));

        // Zero settlements never form batch
        assert!(!rules.should_form_batch(0, 1_000_000, 0));

        // Zero settlements but timeout reached — still no batch (nothing to batch)
        assert!(!rules.should_form_batch(0, 1_000_000, 7 * 60 * 60));

        // High value forces batch
        assert!(rules.should_form_batch(1, 20_000_000_000, 0));
    }
}
