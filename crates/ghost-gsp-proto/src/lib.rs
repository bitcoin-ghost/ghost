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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost GSP Protocol - Shared types for GSP and Light Wallet communication
//!
//! This crate defines the protocol types used for communication between
//! Ghost Service Providers (GSPs) and Light Wallets. It includes:
//!
//! - **Messages**: WebSocket message types for bidirectional communication
//! - **Auth**: WalletProof authentication and session management
//! - **Payment**: Payment preparation and submission types
//! - **Lock**: Ghost Lock information and management types
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────┐          ┌─────────────────────────┐
//! │     Light Wallet        │   WSS    │          GSP            │
//! │  (Keys stay local)      │◄────────►│  (Runs full node)       │
//! │  - Signing              │          │  - Routes payments      │
//! │  - Key management       │          │  - Balance queries      │
//! │  - Address derivation   │          │  - Settlement           │
//! └─────────────────────────┘          └─────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```
//! use ghost_gsp_proto::{ClientMessage, ServerMessage, WalletProof};
//!
//! // Create a balance request
//! let request = ClientMessage::GetBalance { max_k: None };
//!
//! // Serialize for sending
//! let json = serde_json::to_string(&request).unwrap();
//! ```

#![deny(unreachable_pub)]

mod auth;
mod error;
mod lock;
mod messages;
mod payment;
mod validation;

pub use auth::{
    RegisterRequest, RegisterResponse, SessionRequest, SessionResponse, SessionToken, WalletId,
    WalletProof,
};
pub use error::GspProtoError;
pub use lock::{
    GhostLockInfo, GhostLockStatus, JumpPriority, JumpRequest, JumpResponse,
    LockFundingConfirmation, LockRequest, LockResponse, LockStateTransition,
};
pub use messages::{
    CandidateOutput, ClientMessage, ConfidentialNoteInfo, InstantCapability, InstantCondition,
    L2ReorgReason, L2TransactionInfo, LockSnapshot, LockStateChangeType, LockStateSnapshot,
    ReorgLayer, ServerMessage, SignedInstantPayment, TransactionInfo, UtxoInfo,
};
pub use payment::{
    PaymentMode, PaymentReceipt, PaymentStatus, PreparePaymentRequest, PreparePaymentResponse,
    PreparedPayment, SubmitPaymentRequest, SubmitPaymentResponse,
};
pub use validation::{validate_message, validate_raw_message, ValidationResult};

/// GSP Protocol version
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Maximum message size in bytes (1 MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// WalletProof timestamp tolerance in seconds (5 minutes)
pub const PROOF_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_serialization() {
        let msg = ClientMessage::GetBalance { max_k: None };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("get_balance"));

        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, ClientMessage::GetBalance { .. }));
    }

    #[test]
    fn test_server_message_serialization() {
        let msg = ServerMessage::BalanceUpdate {
            confirmed: 100_000,
            unconfirmed: 50_000,
            locked: 25_000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("balance_update"));
        assert!(json.contains("100000"));

        let parsed: ServerMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ServerMessage::BalanceUpdate {
                confirmed,
                unconfirmed,
                locked,
            } => {
                assert_eq!(confirmed, 100_000);
                assert_eq!(unconfirmed, 50_000);
                assert_eq!(locked, 25_000);
            }
            _ => panic!("Wrong message type"),
        }
    }
}
