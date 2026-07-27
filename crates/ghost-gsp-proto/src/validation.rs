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
//| FILE: validation.rs                                                                                                  |
//|======================================================================================================================|

//! Message validation utilities for GSP Protocol
//!
//! Provides validation for protocol messages before processing.

use std::str::FromStr;

use bitcoin::Address;

use crate::error::GspProtoError;
use crate::messages::ClientMessage;
use crate::payment::PaymentMode;
use crate::MAX_MESSAGE_SIZE;

/// Result of message validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation passed
    pub valid: bool,

    /// Validation errors (if any)
    pub errors: Vec<String>,

    /// Validation warnings (non-fatal)
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a successful validation result
    pub fn ok() -> Self {
        ValidationResult {
            valid: true,
            errors: vec![],
            warnings: vec![],
        }
    }

    /// Create a failed validation result
    pub fn fail(error: impl Into<String>) -> Self {
        ValidationResult {
            valid: false,
            errors: vec![error.into()],
            warnings: vec![],
        }
    }

    /// Add an error
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.valid = false;
        self.errors.push(error.into());
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

/// Validate a raw message (before parsing)
pub fn validate_raw_message(data: &[u8]) -> Result<(), GspProtoError> {
    // Check size
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(GspProtoError::MessageTooLarge {
            max: MAX_MESSAGE_SIZE,
        });
    }

    // Check for valid UTF-8
    if std::str::from_utf8(data).is_err() {
        return Err(GspProtoError::InvalidMessageFormat(
            "Invalid UTF-8 encoding".to_string(),
        ));
    }

    Ok(())
}

/// Validate a parsed client message
pub fn validate_message(msg: &ClientMessage) -> ValidationResult {
    let mut result = ValidationResult::ok();

    match msg {
        ClientMessage::Authenticate { token } => {
            if token.is_empty() {
                result.add_error("Token cannot be empty");
            }
            if token.len() > 4096 {
                result.add_error("Token exceeds maximum length");
            }
        }

        ClientMessage::Ping { .. } => {
            // Ping is always valid
        }

        ClientMessage::GetBalance { max_k } => {
            if let Some(k) = max_k {
                if *k == 0 || *k > 10_000 {
                    return ValidationResult {
                        valid: false,
                        errors: vec!["max_k must be between 1 and 10,000".to_string()],
                        warnings: vec![],
                    };
                }
            }
        }

        ClientMessage::GetUtxos { min_confirmations } => {
            if *min_confirmations > 10000 {
                result.add_warning("Very high confirmation requirement");
            }
        }

        ClientMessage::GetGhostLocks => {
            // No parameters to validate
        }

        ClientMessage::GetTransactions {
            limit,
            offset: _,
            wallet_bech32: _,
        } => {
            if *limit == 0 {
                result.add_error("Limit must be greater than 0");
            }
            if *limit > 1000 {
                result.add_error("Limit cannot exceed 1000");
            }
        }

        ClientMessage::PreparePayment {
            recipient,
            amount_sats,
            mode,
            proof,
            memo: _,
            encrypted_metadata: _,
        } => {
            // Validate recipient
            if recipient.is_empty() {
                result.add_error("Recipient cannot be empty");
            } else if !is_valid_recipient(recipient) {
                result.add_error("Invalid recipient format");
            }

            // Validate amount
            if *amount_sats == 0 {
                result.add_error("Amount must be greater than 0");
            }
            if *amount_sats < 546 {
                result.add_warning("Amount below dust threshold");
            }

            // Validate mode-specific constraints
            if *mode == PaymentMode::Wraith && *amount_sats < 10_000 {
                result.add_error("Wraith payments require minimum 10,000 sats");
            }

            // Validate proof structure
            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }

            // Check proof timestamp
            if !proof.is_timestamp_valid() {
                result.add_error("Proof timestamp out of range");
            }
        }

        ClientMessage::SendL2Payment {
            recipient,
            amount_sats,
            proof,
            memo,
        } => {
            if recipient.is_empty() {
                result.add_error("Recipient cannot be empty");
            } else if !is_valid_recipient(recipient) {
                result.add_error("Invalid recipient format");
            }
            if *amount_sats == 0 {
                result.add_error("Amount must be greater than 0");
            }
            if *amount_sats < 546 {
                result.add_warning("Amount below dust threshold");
            }
            if let Some(m) = memo {
                if m.len() > 59 {
                    result.add_error("Memo exceeds 59-char limit");
                }
            }
            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
            if !proof.is_timestamp_valid() {
                result.add_error("Proof timestamp out of range");
            }
        }

        ClientMessage::SubmitSignedPayment {
            payment_id,
            signature,
            public_key,
        } => {
            validate_payment_id(payment_id, &mut result);

            // Validate signature (64 bytes = 128 hex chars)
            if signature.len() != 128 {
                result.add_error("Signature must be 128 hex characters");
            } else if hex::decode(signature).is_err() {
                result.add_error("Invalid signature hex encoding");
            }

            // Validate public key (32 bytes = 64 hex chars)
            if public_key.len() != 64 {
                result.add_error("Public key must be 64 hex characters");
            } else if hex::decode(public_key).is_err() {
                result.add_error("Invalid public key hex encoding");
            }
        }

        ClientMessage::GetPaymentStatus { payment_id, proof } => {
            validate_payment_id(payment_id, &mut result);

            // H-1: Validate proof structure for GetPaymentStatus
            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
        }

        ClientMessage::CancelPayment { payment_id, proof } => {
            validate_payment_id(payment_id, &mut result);

            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
        }

        ClientMessage::PrepareGhostLock {
            owner_pubkey,
            capacity_sats,
            recovery_pubkey,
            recovery_index: _,
        } => {
            // Validate owner pubkey (32 bytes x-only = 64 hex chars)
            if owner_pubkey.len() != 64 {
                result.add_error("Owner pubkey must be 64 hex characters");
            } else if hex::decode(owner_pubkey).is_err() {
                result.add_error("Invalid owner pubkey hex encoding");
            }

            // Validate recovery pubkey (33-byte SEC1 compressed = 66 hex chars).
            // Must start with 02 or 03 (compressed prefix) — uncompressed (04)
            // is rejected.
            if recovery_pubkey.len() != 66 {
                result.add_error(
                    "recovery_pubkey must be 66 hex characters (33-byte SEC1 compressed)",
                );
            } else {
                match hex::decode(recovery_pubkey) {
                    Ok(bytes) if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) => {}
                    Ok(_) => result
                        .add_error("recovery_pubkey must be SEC1-compressed (0x02/0x03 prefix)"),
                    Err(_) => result.add_error("Invalid recovery_pubkey hex encoding"),
                }
            }

            // Validate capacity
            if *capacity_sats < 546 {
                result.add_error("Capacity must be at least 546 sats (dust limit)");
            }
            if *capacity_sats > 1_000_000_000_000 {
                result.add_error("Capacity exceeds maximum (10 BTC)");
            }
        }

        ClientMessage::ConfirmGhostLockFunding {
            lock_id,
            funding_txid,
            proof,
        } => {
            if lock_id.is_empty() {
                result.add_error("Lock ID cannot be empty");
            }

            // Validate txid (32 bytes = 64 hex chars)
            if funding_txid.len() != 64 {
                result.add_error("Funding txid must be 64 hex characters");
            } else if hex::decode(funding_txid).is_err() {
                result.add_error("Invalid funding txid hex encoding");
            }

            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
        }

        ClientMessage::RegisterScanKey { scan_pubkey, proof } => {
            // 33-byte SEC1 compressed pubkey = 66 hex chars.
            if scan_pubkey.len() != 66 {
                result.add_error("scan_pubkey must be 66 hex chars (33 bytes SEC1 compressed)");
            } else if hex::decode(scan_pubkey).is_err() {
                result.add_error("scan_pubkey is not valid hex");
            }
            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
        }

        ClientMessage::RequestJump {
            lock_id,
            priority,
            target_address,
            proof,
        } => {
            if lock_id.is_empty() {
                result.add_error("Lock ID cannot be empty");
            }

            // MED-VALIDATE-2 FIX: Normalize priority to lowercase before comparison
            // This ensures case-insensitive matching (e.g., "High", "HIGH", "high" all valid)
            let priority_lower = priority.to_lowercase();
            let valid_priorities = ["normal", "high", "urgent"];
            if !valid_priorities.contains(&priority_lower.as_str()) {
                result.add_error(
                    "Invalid priority (must be normal, high, or urgent - case insensitive)",
                );
            }

            // Validate target address
            if !is_valid_bitcoin_address(target_address) {
                result.add_error("Invalid target address");
            }

            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
        }

        ClientMessage::SubscribeBalance
        | ClientMessage::SubscribePayments
        | ClientMessage::SubscribeLocks
        | ClientMessage::SubscribeReorgs
        | ClientMessage::UnsubscribeReorgs
        | ClientMessage::SubscribeSilentPayments
        | ClientMessage::UnsubscribeSilentPayments => {
            // No parameters to validate
        }

        ClientMessage::Unsubscribe { subscription } => {
            let valid_subscriptions = ["balance", "payments", "locks", "lock_state", "reorgs"];
            if !valid_subscriptions.contains(&subscription.to_lowercase().as_str()) {
                result.add_error("Invalid subscription type");
            }
        }

        // =========================================================================
        // Instant Payment Messages
        // =========================================================================
        ClientMessage::CheckInstantCapability {
            lock_id,
            amount_sats,
        } => {
            if lock_id.is_empty() {
                result.add_error("Lock ID cannot be empty");
            }
            if *amount_sats == 0 {
                result.add_error("Amount must be greater than 0");
            }
            // Cap at instant limit (100k sats)
            if *amount_sats > 100_000 {
                result.add_warning("Amount exceeds instant payment limit (100,000 sats)");
            }
        }

        ClientMessage::SubscribeLockState { lock_id } => {
            if lock_id.is_empty() {
                result.add_error("Lock ID cannot be empty");
            }
        }

        ClientMessage::UnsubscribeLockState { lock_id } => {
            if lock_id.is_empty() {
                result.add_error("Lock ID cannot be empty");
            }
        }

        ClientMessage::AcceptInstantPayment {
            sender_lock_id,
            amount_sats,
            proof,
            signed_payment,
        } => {
            if sender_lock_id.is_empty() {
                result.add_error("Sender lock ID cannot be empty");
            }
            if *amount_sats == 0 {
                result.add_error("Amount must be greater than 0");
            }
            // Instant payments capped at 100k sats
            if *amount_sats > 100_000 {
                result.add_error("Amount exceeds instant payment limit (100,000 sats)");
            }

            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }

            if !proof.is_timestamp_valid() {
                result.add_error("Proof timestamp out of range");
            }

            // M-9 FIX: Validate signed_payment structure
            // Verify sender_lock_id matches
            if signed_payment.sender_lock_id != *sender_lock_id {
                result.add_error("Signed payment sender_lock_id must match request sender_lock_id");
            }
            // Verify amount matches
            if signed_payment.amount_sats != *amount_sats {
                result.add_error("Signed payment amount must match request amount");
            }
            // Verify signature is not empty (64 bytes)
            if signed_payment.signature == [0u8; 64] {
                result.add_error("Signed payment signature cannot be empty");
            }
            // Verify sender pubkey is not empty (32 bytes)
            if signed_payment.sender_pubkey == [0u8; 32] {
                result.add_error("Signed payment sender pubkey cannot be empty");
            }
        }

        // =========================================================================
        // Confidential Transfer Messages
        // =========================================================================
        ClientMessage::SubmitConfidentialTransfer {
            proof_hex,
            old_commitment_root,
            new_commitment_root,
            nullifier,
            sender_new_commitment,
            recipient_new_commitment,
            sender_index: _,
            recipient_index: _,
            recipient_owner_pubkey,
        } => {
            // Proof must be 192 bytes = 384 hex chars
            if proof_hex.len() != 384 {
                result.add_error("Proof must be 384 hex characters (192 bytes)");
            } else if hex::decode(proof_hex).is_err() {
                result.add_error("Invalid proof hex encoding");
            }
            // All 32-byte fields must be 64 hex chars
            for (name, val) in [
                ("old_commitment_root", old_commitment_root.as_str()),
                ("new_commitment_root", new_commitment_root.as_str()),
                ("nullifier", nullifier.as_str()),
                ("sender_new_commitment", sender_new_commitment.as_str()),
                (
                    "recipient_new_commitment",
                    recipient_new_commitment.as_str(),
                ),
                ("recipient_owner_pubkey", recipient_owner_pubkey.as_str()),
            ] {
                if val.len() != 64 {
                    result.add_error(format!("{} must be 64 hex characters", name));
                } else if hex::decode(val).is_err() {
                    result.add_error(format!("Invalid {} hex encoding", name));
                }
            }
        }

        ClientMessage::ShieldBalance {
            amount_sats,
            blinding_hex,
            owner_pubkey,
            proof,
        } => {
            if *amount_sats == 0 {
                result.add_error("Amount must be greater than 0");
            }
            if blinding_hex.len() != 64 {
                result.add_error("Blinding must be 64 hex characters (32 bytes)");
            } else if hex::decode(blinding_hex).is_err() {
                result.add_error("Invalid blinding hex encoding");
            }
            if owner_pubkey.len() != 64 {
                result.add_error("Owner pubkey must be 64 hex characters");
            } else if hex::decode(owner_pubkey).is_err() {
                result.add_error("Invalid owner pubkey hex encoding");
            }
            if let Err(e) = proof.validate_structure() {
                result.add_error(format!("Invalid proof: {}", e));
            }
        }

        ClientMessage::GetCommitmentTreeState => {
            // No parameters to validate
        }

        ClientMessage::GetConfidentialNotes { owner_pubkey } => {
            if owner_pubkey.len() != 64 {
                result.add_error("Owner pubkey must be 64 hex characters");
            } else if hex::decode(owner_pubkey).is_err() {
                result.add_error("Invalid owner pubkey hex encoding");
            }
        }

        ClientMessage::SubscribeConfidential => {
            // No parameters to validate
        }

        ClientMessage::GetRecentL2Transactions { .. } => {
            // since_height is a u64, no validation needed
        }
    }

    result
}

/// Validate payment ID format
///
/// Payment IDs must be:
/// - Non-empty
/// - At most 128 characters
/// - Only contain alphanumeric characters, hyphens, or underscores
///
/// HIGH-VALIDATE-1 FIX: Explicitly reject path traversal characters
/// to prevent directory traversal attacks when payment IDs are used in file paths.
fn validate_payment_id(id: &str, result: &mut ValidationResult) {
    if id.is_empty() {
        result.add_error("Payment ID cannot be empty");
        return;
    }

    if id.len() > 128 {
        result.add_error("Payment ID exceeds 128 character limit");
        return;
    }

    // HIGH-VALIDATE-1: Explicitly check for path traversal characters FIRST
    // These checks are explicit to make the security properties clear
    if id.contains('/') {
        result.add_error("Payment ID cannot contain '/' (path traversal risk)");
        return;
    }
    if id.contains('\\') {
        result.add_error("Payment ID cannot contain '\\' (path traversal risk)");
        return;
    }
    if id.contains('.') {
        result.add_error("Payment ID cannot contain '.' (path traversal risk)");
        return;
    }
    if id.contains('\0') {
        result.add_error("Payment ID cannot contain null bytes");
        return;
    }

    // After path traversal checks, validate allowed character set
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        result.add_error("Payment ID contains invalid characters (allowed: alphanumeric, -, _)");
    }
}

/// Check if recipient is a valid Ghost ID or Bitcoin address
fn is_valid_recipient(recipient: &str) -> bool {
    // Ghost ID format: <network>ghost1... where the network prefix is
    // empty on mainnet (`ghost1`), `t` on testnet (`tghost1`), `s` on
    // signet (`sghost1`), or `r` on regtest (`rghost1`).
    if recipient.contains("ghost1") {
        let i = recipient.find("ghost1").unwrap();
        // Allow only an empty prefix or one of the single-letter
        // network discriminators — anything else is a malformed ID.
        let prefix = &recipient[..i];
        let ok = matches!(prefix, "" | "t" | "s" | "r");
        if ok && recipient.len() >= 20 && recipient.len() <= 130 {
            return true;
        }
    }

    // Bitcoin address
    is_valid_bitcoin_address(recipient)
}

/// Check if string is a valid Bitcoin address
///
/// LOW FIX: Uses bitcoin crate's Address::from_str() for full validation
/// including checksum verification. This prevents accepting malformed
/// addresses that could cause payment failures.
fn is_valid_bitcoin_address(address: &str) -> bool {
    // LOW FIX: Use bitcoin crate's Address parsing which validates:
    // - Correct prefix for network (bc1, tb1, bcrt1, 1, 3, m, n, 2)
    // - Valid bech32/bech32m checksum for segwit addresses
    // - Valid base58check checksum for legacy addresses
    // - Correct length and format
    //
    // We use Address::from_str with Unchecked network because we accept
    // addresses from any Bitcoin network (mainnet, testnet, signet, regtest).
    Address::<bitcoin::address::NetworkUnchecked>::from_str(address).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::WalletProof;

    #[test]
    fn test_validation_result_ok() {
        let result = ValidationResult::ok();
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validation_result_fail() {
        let result = ValidationResult::fail("Test error");
        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_validate_raw_message_size() {
        let small = vec![0u8; 100];
        assert!(validate_raw_message(&small).is_ok());

        let large = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(validate_raw_message(&large).is_err());
    }

    #[test]
    fn test_validate_raw_message_utf8() {
        let valid = b"hello world";
        assert!(validate_raw_message(valid).is_ok());

        let invalid = vec![0xff, 0xfe, 0x00];
        assert!(validate_raw_message(&invalid).is_err());
    }

    #[test]
    fn test_validate_get_balance() {
        let msg = ClientMessage::GetBalance { max_k: None };
        let result = validate_message(&msg);
        assert!(result.valid);

        let msg = ClientMessage::GetBalance { max_k: Some(100) };
        let result = validate_message(&msg);
        assert!(result.valid);

        let msg = ClientMessage::GetBalance { max_k: Some(0) };
        let result = validate_message(&msg);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_get_transactions() {
        let msg = ClientMessage::GetTransactions {
            limit: 100,
            offset: 0,
            wallet_bech32: None,
        };
        let result = validate_message(&msg);
        assert!(result.valid);

        let msg2 = ClientMessage::GetTransactions {
            limit: 0,
            offset: 0,
            wallet_bech32: None,
        };
        let result2 = validate_message(&msg2);
        assert!(!result2.valid);

        let msg3 = ClientMessage::GetTransactions {
            limit: 2000,
            offset: 0,
            wallet_bech32: None,
        };
        let result3 = validate_message(&msg3);
        assert!(!result3.valid);
    }

    #[test]
    fn test_is_valid_bitcoin_address() {
        // Valid addresses
        assert!(is_valid_bitcoin_address(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));
        assert!(is_valid_bitcoin_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        ));
        assert!(is_valid_bitcoin_address(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ));

        // Invalid addresses
        assert!(!is_valid_bitcoin_address("invalid"));
        assert!(!is_valid_bitcoin_address(""));
    }

    #[test]
    fn test_is_valid_recipient() {
        // Ghost ID
        assert!(is_valid_recipient(
            "ghost1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));

        // Bitcoin address
        assert!(is_valid_recipient(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));

        // Invalid
        assert!(!is_valid_recipient("invalid"));
    }

    #[test]
    fn test_validate_submit_signed_payment() {
        let msg = ClientMessage::SubmitSignedPayment {
            payment_id: "test123".to_string(),
            signature: hex::encode([0u8; 64]),
            public_key: hex::encode([1u8; 32]),
        };
        let result = validate_message(&msg);
        assert!(result.valid);

        // Invalid signature length
        let msg2 = ClientMessage::SubmitSignedPayment {
            payment_id: "test123".to_string(),
            signature: "invalid".to_string(),
            public_key: hex::encode([1u8; 32]),
        };
        let result2 = validate_message(&msg2);
        assert!(!result2.valid);
    }

    /// Helper to create a valid test WalletProof
    fn test_wallet_proof() -> WalletProof {
        let pubkey = [1u8; 32];
        let mut proof =
            WalletProof::new("get_payment_status", &pubkey).expect("nonce generation failed");
        proof.signature = hex::encode([2u8; 64]); // Valid signature format
        proof
    }

    #[test]
    fn test_l11_payment_id_validation() {
        // L-11: Test payment ID validation

        // Valid payment IDs
        let msg = ClientMessage::GetPaymentStatus {
            payment_id: "valid-payment_123".to_string(),
            proof: test_wallet_proof(),
        };
        let result = validate_message(&msg);
        assert!(result.valid, "Should accept valid payment ID");

        // Empty payment ID
        let msg = ClientMessage::GetPaymentStatus {
            payment_id: "".to_string(),
            proof: test_wallet_proof(),
        };
        let result = validate_message(&msg);
        assert!(!result.valid, "Should reject empty payment ID");
        assert!(result.errors.iter().any(|e| e.contains("empty")));

        // Payment ID too long (>128 chars)
        let msg = ClientMessage::GetPaymentStatus {
            payment_id: "a".repeat(129),
            proof: test_wallet_proof(),
        };
        let result = validate_message(&msg);
        assert!(!result.valid, "Should reject payment ID over 128 chars");
        assert!(result.errors.iter().any(|e| e.contains("128")));

        // Payment ID with invalid characters
        let msg = ClientMessage::GetPaymentStatus {
            payment_id: "payment@id!with#invalid$chars".to_string(),
            proof: test_wallet_proof(),
        };
        let result = validate_message(&msg);
        assert!(!result.valid, "Should reject payment ID with invalid chars");
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("invalid characters")));

        // Payment ID at exactly 128 chars (boundary - should pass)
        let msg = ClientMessage::GetPaymentStatus {
            payment_id: "a".repeat(128),
            proof: test_wallet_proof(),
        };
        let result = validate_message(&msg);
        assert!(
            result.valid,
            "Should accept payment ID at exactly 128 chars"
        );

        // Valid payment ID with all allowed characters
        let msg = ClientMessage::GetPaymentStatus {
            payment_id: "abc-XYZ_123-payment_ID".to_string(),
            proof: test_wallet_proof(),
        };
        let result = validate_message(&msg);
        assert!(
            result.valid,
            "Should accept alphanumeric, hyphen, underscore"
        );
    }
}
