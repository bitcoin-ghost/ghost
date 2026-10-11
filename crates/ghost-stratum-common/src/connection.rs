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
//| FILE: connection.rs                                                                                                  |
//|======================================================================================================================|

//! Connection management for Stratum V1 and V2.
//!
//! This module provides connection abstractions for both protocols:
//! - `Sv1Connection`: JSON-RPC over TCP for legacy miners
//! - `Sv2Connection`: Binary with Noise encryption for modern miners

use crate::error::{Result, StratumError};
use crate::sv1_api::json_rpc;
use async_channel::{unbounded, Receiver, Sender};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tracing::{debug, error, trace, warn};

/// Maximum line length for SV1 JSON-RPC messages.
const MAX_LINE_LENGTH: usize = 1 << 16;

// ============================================================================
// Stratum V1 Connection
// ============================================================================

/// A connection for Stratum V1 (JSON-RPC over TCP).
///
/// This is a bidirectional connection that handles reading and writing
/// JSON-RPC messages asynchronously using channels.
///
/// # Example
///
/// ```ignore
/// use ghost_stratum_common::connection::Sv1Connection;
/// use tokio::net::TcpStream;
///
/// let stream = TcpStream::connect("pool.example.com:3333").await?;
/// let conn = Sv1Connection::new(stream).await;
///
/// // Send a message
/// conn.send(mining_subscribe_request).await;
///
/// // Receive a response
/// if let Some(response) = conn.receive().await {
///     // Handle response
/// }
/// ```
#[derive(Debug)]
pub struct Sv1Connection {
    /// Channel for receiving incoming messages.
    receiver: Receiver<json_rpc::Message>,
    /// Channel for sending outgoing messages.
    sender: Sender<json_rpc::Message>,
}

impl Sv1Connection {
    /// Create a new SV1 connection from a TCP stream.
    ///
    /// This spawns background tasks for reading and writing,
    /// returning a connection handle for sending/receiving messages.
    pub async fn new(stream: TcpStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        let (sender_incoming, receiver_incoming) = unbounded();
        let (sender_outgoing, receiver_outgoing) = unbounded();

        let buffer_read_half = BufReader::new(read_half);
        let buffer_write_half = BufWriter::new(write_half);

        // Spawn reader task
        let sender_for_reader = sender_incoming.clone();
        tokio::spawn(async move {
            Self::run_reader(buffer_read_half, sender_for_reader).await;
        });

        // Spawn writer task
        tokio::spawn(async move {
            Self::run_writer(buffer_write_half, receiver_outgoing).await;
        });

        Self {
            receiver: receiver_incoming,
            sender: sender_outgoing,
        }
    }

    /// Reader task: reads JSON-RPC messages from the stream.
    async fn run_reader(
        reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
        sender: Sender<json_rpc::Message>,
    ) {
        let mut lines = reader.lines();

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.len() > MAX_LINE_LENGTH {
                        warn!("SV1 message too long ({} bytes), dropping", line.len());
                        continue;
                    }

                    match serde_json::from_str::<json_rpc::Message>(&line) {
                        Ok(msg) => {
                            trace!("SV1 received: {:?}", msg);
                            if sender.send(msg).await.is_err() {
                                debug!("SV1 reader: receiver dropped, stopping");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("SV1 failed to parse message: {}", e);
                        }
                    }
                }
                Ok(None) => {
                    debug!("SV1 connection closed by peer");
                    break;
                }
                Err(e) => {
                    error!("SV1 read error: {}", e);
                    break;
                }
            }
        }

        sender.close();
    }

    /// Writer task: writes JSON-RPC messages to the stream.
    async fn run_writer(
        mut writer: BufWriter<tokio::net::tcp::OwnedWriteHalf>,
        receiver: Receiver<json_rpc::Message>,
    ) {
        while let Ok(msg) = receiver.recv().await {
            match serde_json::to_string(&msg) {
                Ok(line) => {
                    trace!("SV1 sending: {}", line);
                    let data = format!("{}\n", line);
                    if let Err(e) = writer.write_all(data.as_bytes()).await {
                        error!("SV1 write error: {}", e);
                        break;
                    }
                    if let Err(e) = writer.flush().await {
                        error!("SV1 flush error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("SV1 failed to serialize message: {}", e);
                }
            }
        }

        debug!("SV1 writer task exiting");
    }

    /// Send a message to the peer.
    ///
    /// Returns `true` if the message was queued successfully.
    pub async fn send(&self, msg: json_rpc::Message) -> bool {
        self.sender.send(msg).await.is_ok()
    }

    /// Receive a message from the peer.
    ///
    /// Returns `None` if the connection was closed.
    pub async fn receive(&self) -> Option<json_rpc::Message> {
        self.receiver.recv().await.ok()
    }

    /// Get a clone of the receiver channel.
    pub fn receiver(&self) -> Receiver<json_rpc::Message> {
        self.receiver.clone()
    }

    /// Get a clone of the sender channel.
    pub fn sender(&self) -> Sender<json_rpc::Message> {
        self.sender.clone()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.receiver.is_closed() || self.sender.is_closed()
    }
}

// ============================================================================
// SV1 Message Builders
// ============================================================================

/// Build a mining.subscribe request.
pub fn build_sv1_subscribe(id: u64, user_agent: &str, extranonce1: Option<&str>) -> json_rpc::Message {
    let params = if let Some(en1) = extranonce1 {
        serde_json::json!([user_agent, en1])
    } else {
        serde_json::json!([user_agent])
    };

    json_rpc::Message::StandardRequest(json_rpc::StandardRequest {
        id,
        method: "mining.subscribe".to_string(),
        params,
    })
}

/// Build a mining.authorize request.
pub fn build_sv1_authorize(id: u64, username: &str, password: &str) -> json_rpc::Message {
    json_rpc::Message::StandardRequest(json_rpc::StandardRequest {
        id,
        method: "mining.authorize".to_string(),
        params: serde_json::json!([username, password]),
    })
}

/// Build a client.reconnect notification to redirect miner.
pub fn build_sv1_reconnect(host: &str, port: u16, wait_time: u32) -> json_rpc::Message {
    json_rpc::Message::Notification(json_rpc::Notification {
        method: "client.reconnect".to_string(),
        params: serde_json::json!([host, port, wait_time]),
    })
}

/// Build a mining.set_difficulty notification.
pub fn build_sv1_set_difficulty(difficulty: f64) -> json_rpc::Message {
    json_rpc::Message::Notification(json_rpc::Notification {
        method: "mining.set_difficulty".to_string(),
        params: serde_json::json!([difficulty]),
    })
}

// ============================================================================
// Message Type Extraction Helpers (CRIT-8: Safe Message Dispatch)
// ============================================================================
//
// These helpers provide safe extraction of message types without panicking.
// Use these instead of if-let/else patterns with panic!() to ensure
// graceful handling of protocol violations.

/// Get the message type name for error reporting.
fn message_type_name(msg: &json_rpc::Message) -> &'static str {
    match msg {
        json_rpc::Message::StandardRequest(_) => "StandardRequest",
        json_rpc::Message::Notification(_) => "Notification",
        json_rpc::Message::OkResponse(_) => "OkResponse",
        json_rpc::Message::ErrorResponse(_) => "ErrorResponse",
    }
}

/// Extract a StandardRequest from a message, returning an error on type mismatch.
///
/// Use this instead of `if let Message::StandardRequest(req) = msg { ... } else { panic!() }`.
///
/// # Example
/// ```ignore
/// let msg: json_rpc::Message = receive_message().await?;
/// let request = extract_standard_request(msg)?;
/// // Handle request...
/// ```
pub fn extract_standard_request(msg: json_rpc::Message) -> Result<json_rpc::StandardRequest> {
    match msg {
        json_rpc::Message::StandardRequest(req) => Ok(req),
        other => Err(StratumError::UnexpectedMessageType {
            expected: "StandardRequest",
            got: message_type_name(&other).to_string(),
        }),
    }
}

/// Extract a Notification from a message, returning an error on type mismatch.
///
/// Use this instead of `if let Message::Notification(n) = msg { ... } else { panic!() }`.
pub fn extract_notification(msg: json_rpc::Message) -> Result<json_rpc::Notification> {
    match msg {
        json_rpc::Message::Notification(notif) => Ok(notif),
        other => Err(StratumError::UnexpectedMessageType {
            expected: "Notification",
            got: message_type_name(&other).to_string(),
        }),
    }
}

/// Extract an OkResponse from a message, returning an error on type mismatch.
pub fn extract_ok_response(msg: json_rpc::Message) -> Result<json_rpc::Response> {
    match msg {
        json_rpc::Message::OkResponse(resp) => Ok(resp),
        other => Err(StratumError::UnexpectedMessageType {
            expected: "OkResponse",
            got: message_type_name(&other).to_string(),
        }),
    }
}

/// Extract an ErrorResponse from a message, returning an error on type mismatch.
pub fn extract_error_response(msg: json_rpc::Message) -> Result<json_rpc::Response> {
    match msg {
        json_rpc::Message::ErrorResponse(resp) => Ok(resp),
        other => Err(StratumError::UnexpectedMessageType {
            expected: "ErrorResponse",
            got: message_type_name(&other).to_string(),
        }),
    }
}

/// Extract any response (Ok or Error) from a message.
pub fn extract_response(msg: json_rpc::Message) -> Result<json_rpc::Response> {
    match msg {
        json_rpc::Message::OkResponse(resp) | json_rpc::Message::ErrorResponse(resp) => Ok(resp),
        other => Err(StratumError::UnexpectedMessageType {
            expected: "Response (OkResponse or ErrorResponse)",
            got: message_type_name(&other).to_string(),
        }),
    }
}

// ============================================================================
// Stratum V2 Connection (placeholder - full implementation needs noise_sv2)
// ============================================================================

/// Placeholder for SV2 connection.
///
/// The full implementation requires integration with noise_sv2 for
/// encrypted connections. See the stratum-apps crate in the original
/// ghost-mining for the complete implementation.
///
/// Key components needed:
/// - `NoiseTcpStream` - Noise-encrypted TCP stream
/// - `HandshakeRole` - Initiator or Responder
/// - Frame encoding/decoding via codec_sv2
#[derive(Debug)]
pub struct Sv2ConnectionConfig {
    /// Authority public key for initiator mode (client).
    pub authority_pubkey: Option<[u8; 32]>,
    /// Private key for responder mode (server).
    pub private_key: Option<[u8; 32]>,
    /// Whether this is a server (responder) or client (initiator).
    pub is_server: bool,
}

impl Default for Sv2ConnectionConfig {
    fn default() -> Self {
        Self {
            authority_pubkey: None,
            private_key: None,
            is_server: false,
        }
    }
}

/// Validate an SV2 configuration.
pub fn validate_sv2_config(config: &Sv2ConnectionConfig) -> Result<()> {
    if config.is_server && config.private_key.is_none() {
        return Err(StratumError::InvalidConfig(
            "Server mode requires private_key".into(),
        ));
    }
    if !config.is_server && config.authority_pubkey.is_none() {
        return Err(StratumError::InvalidConfig(
            "Client mode requires authority_pubkey".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // CRIT-8: Tests now use extract_* helpers instead of panic!()
    // This demonstrates proper error handling patterns for production code
    // =========================================================================

    #[test]
    fn test_build_sv1_subscribe() {
        let msg = build_sv1_subscribe(1, "ghost-miner/1.0", None);
        // Use extract_standard_request for safe extraction
        let req = extract_standard_request(msg).expect("should be StandardRequest");
        assert_eq!(req.id, 1);
        assert_eq!(req.method, "mining.subscribe");
    }

    #[test]
    fn test_build_sv1_authorize() {
        let msg = build_sv1_authorize(2, "bc1qtest", "x");
        // Use extract_standard_request for safe extraction
        let req = extract_standard_request(msg).expect("should be StandardRequest");
        assert_eq!(req.id, 2);
        assert_eq!(req.method, "mining.authorize");
    }

    #[test]
    fn test_build_sv1_reconnect() {
        let msg = build_sv1_reconnect("pool2.example.com", 3334, 0);
        // Use extract_notification for safe extraction
        let notif = extract_notification(msg).expect("should be Notification");
        assert_eq!(notif.method, "client.reconnect");
    }

    #[test]
    fn test_build_sv1_set_difficulty() {
        let msg = build_sv1_set_difficulty(65536.0);
        // Use extract_notification for safe extraction
        let notif = extract_notification(msg).expect("should be Notification");
        assert_eq!(notif.method, "mining.set_difficulty");
    }

    // =========================================================================
    // CRIT-8: Tests proving malformed messages return errors, not panics
    // =========================================================================

    #[test]
    fn test_extract_request_from_notification_returns_error() {
        // Create a Notification
        let msg = build_sv1_set_difficulty(1.0);
        // Try to extract as StandardRequest - should error, not panic
        let result = extract_standard_request(msg);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StratumError::UnexpectedMessageType { .. }));
    }

    #[test]
    fn test_extract_notification_from_request_returns_error() {
        // Create a StandardRequest
        let msg = build_sv1_subscribe(1, "test", None);
        // Try to extract as Notification - should error, not panic
        let result = extract_notification(msg);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StratumError::UnexpectedMessageType { .. }));
    }

    #[test]
    fn test_extract_response_from_request_returns_error() {
        // Create a StandardRequest
        let msg = build_sv1_authorize(1, "user", "pass");
        // Try to extract as Response - should error, not panic
        let result = extract_response(msg);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            StratumError::UnexpectedMessageType { expected, got } => {
                assert!(expected.contains("Response"));
                assert_eq!(got, "StandardRequest");
            }
            _ => panic!("Expected UnexpectedMessageType error"),
        }
    }

    #[test]
    fn test_unexpected_message_type_error_message() {
        let msg = build_sv1_reconnect("host", 3333, 0);
        let err = extract_standard_request(msg).unwrap_err();
        let error_string = err.to_string();
        // Verify error message is informative
        assert!(error_string.contains("Unexpected message type"));
        assert!(error_string.contains("StandardRequest"));
        assert!(error_string.contains("Notification"));
    }

    #[test]
    fn test_sv2_config_validation() {
        // Server without private key should fail
        let config = Sv2ConnectionConfig {
            is_server: true,
            private_key: None,
            ..Default::default()
        };
        assert!(validate_sv2_config(&config).is_err());

        // Client without authority pubkey should fail
        let config = Sv2ConnectionConfig {
            is_server: false,
            authority_pubkey: None,
            ..Default::default()
        };
        assert!(validate_sv2_config(&config).is_err());

        // Valid server config
        let config = Sv2ConnectionConfig {
            is_server: true,
            private_key: Some([1u8; 32]),
            ..Default::default()
        };
        assert!(validate_sv2_config(&config).is_ok());

        // Valid client config
        let config = Sv2ConnectionConfig {
            is_server: false,
            authority_pubkey: Some([2u8; 32]),
            ..Default::default()
        };
        assert!(validate_sv2_config(&config).is_ok());
    }
}
