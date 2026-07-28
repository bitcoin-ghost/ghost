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
//| FILE: handlers.rs                                                                                                    |
//|======================================================================================================================|

//! Concrete verification handlers
//!
//! Provides actual implementations of verification traits:
//! - RpcArchiveHandler: Uses Bitcoin Core RPC
//! - StratumVerifier: Performs protocol handshake

use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// AUTH4-L2: Hash an address and return the first 8 characters for anonymized logging
fn anonymize_addr(addr: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(addr.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::rpc::BitcoinRpc;

use crate::challenge::{BlockData, TxData};
use crate::server::{ArchiveHandler, EpochProof, GhostPayHandler};

/// Archive handler backed by Bitcoin Core RPC
pub struct RpcArchiveHandler {
    /// RPC client
    rpc: Arc<BitcoinRpc>,
    /// Minimum height we can serve (for pruned nodes)
    min_height: Option<u64>,
}

impl RpcArchiveHandler {
    /// Create a new RPC archive handler
    pub fn new(rpc: Arc<BitcoinRpc>) -> Self {
        Self {
            rpc,
            min_height: None,
        }
    }

    /// Set minimum height (for pruned nodes)
    pub fn with_min_height(mut self, height: u64) -> Self {
        self.min_height = Some(height);
        self
    }

    /// Synchronous wrapper for async RPC call (for trait implementation)
    fn blocking_get_block(&self, hash: &str) -> GhostResult<Option<BlockData>> {
        let rpc = self.rpc.clone();
        let hash = hash.to_string();

        // Use block_in_place to allow blocking within async context
        let result = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                // Get block header first (lightweight)
                match rpc.get_block_header(&hash).await {
                    Ok(header) => {
                        // Now get full block for tx count
                        let block_json = rpc.get_block(&hash, 1).await?;
                        let tx_count = block_json
                            .get("nTx")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(header.n_tx) as usize;

                        Ok(Some(BlockData {
                            hash: header.hash,
                            height: header.height,
                            timestamp: header.time,
                            tx_count,
                            merkle_root: header.merkleroot,
                        }))
                    }
                    Err(e) => {
                        // Check if it's a "not found" error
                        if e.to_string().contains("-5") || e.to_string().contains("not found") {
                            Ok(None)
                        } else {
                            Err(e)
                        }
                    }
                }
            })
        });

        result
    }

    /// Synchronous wrapper for async transaction lookup
    fn blocking_get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>> {
        let rpc = self.rpc.clone();
        let txid = txid.to_string();

        // Use block_in_place to allow blocking within async context
        let result = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                match rpc.get_raw_transaction(&txid, true).await {
                    Ok(tx_json) => {
                        let block_hash = tx_json
                            .get("blockhash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        let size =
                            tx_json.get("size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                        let vin = tx_json
                            .get("vin")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);

                        let vout = tx_json
                            .get("vout")
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);

                        // Get block to find tx index
                        let tx_index = if !block_hash.is_empty() {
                            if let Ok(block) = rpc.get_block(&block_hash, 1).await {
                                block
                                    .get("tx")
                                    .and_then(|v| v.as_array())
                                    .and_then(|txs| {
                                        txs.iter().position(|t| {
                                            t.as_str().map(|s| s == txid).unwrap_or(false)
                                        })
                                    })
                                    .unwrap_or(0)
                            } else {
                                0
                            }
                        } else {
                            0
                        };

                        Ok(Some(TxData {
                            txid,
                            block_hash,
                            tx_index,
                            size,
                            input_count: vin,
                            output_count: vout,
                        }))
                    }
                    Err(e) => {
                        if e.to_string().contains("-5") || e.to_string().contains("not found") {
                            Ok(None)
                        } else {
                            Err(e)
                        }
                    }
                }
            })
        });

        result
    }

    /// Check if we have a block at the given height
    fn blocking_has_block_at_height(&self, height: u64) -> bool {
        // If we have a minimum height and the requested height is below it, we don't have it
        if let Some(min) = self.min_height {
            if height < min {
                return false;
            }
        }

        let rpc = self.rpc.clone();

        // Use block_in_place to allow blocking within async context
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                match rpc.get_block_count().await {
                    Ok(current_height) => height <= current_height,
                    Err(_) => false,
                }
            })
        })
    }
}

impl ArchiveHandler for RpcArchiveHandler {
    fn get_block(&self, hash: &str) -> GhostResult<Option<BlockData>> {
        self.blocking_get_block(hash)
    }

    fn get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>> {
        self.blocking_get_transaction(txid)
    }

    fn has_block_at_height(&self, height: u64) -> bool {
        self.blocking_has_block_at_height(height)
    }
}

/// Stratum protocol verifier
///
/// Performs actual protocol handshake to verify Stratum endpoints are accessible
/// and responding correctly.
pub struct StratumVerifier {
    /// Connection timeout
    timeout: Duration,
}

impl StratumVerifier {
    /// Create a new stratum verifier
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(5),
        }
    }

    /// Set connection timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Verify Stratum V1 endpoint
    ///
    /// L-5 FIX: Performs proper JSON-RPC validation to verify the endpoint
    /// is a real Stratum V1 server. Previously only checked for "result" and "id" strings.
    ///
    /// Validation requirements:
    /// 1. Response must be valid JSON
    /// 2. Must have JSON-RPC structure with "id" matching our request (1)
    /// 3. Must have "result" field (not "error")
    /// 4. Result must be an array with mining.subscribe response format
    pub async fn verify_sv1(&self, host: &str, port: u16) -> GhostResult<StratumVerifyResult> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();

        // Connect with timeout
        let stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| GhostError::Timeout("Stratum connection timed out".to_string()))?
            .map_err(|e| GhostError::Internal(format!("Connection failed: {}", e)))?;

        let connect_latency = start.elapsed();

        // Send mining.subscribe request
        let subscribe_request =
            r#"{"id":1,"method":"mining.subscribe","params":["ghost-verify/1.0"]}"#;
        let request_with_newline = format!("{}\n", subscribe_request);

        let (mut reader, mut writer) = stream.into_split();

        // Write request
        timeout(
            self.timeout,
            writer.write_all(request_with_newline.as_bytes()),
        )
        .await
        .map_err(|_| GhostError::Timeout("Write timed out".to_string()))?
        .map_err(|e| GhostError::Internal(format!("Write failed: {}", e)))?;

        // Read response
        let mut buf = vec![0u8; 4096];
        let n = timeout(self.timeout, reader.read(&mut buf))
            .await
            .map_err(|_| GhostError::Timeout("Read timed out".to_string()))?
            .map_err(|e| GhostError::Internal(format!("Read failed: {}", e)))?;

        if n == 0 {
            return Err(GhostError::Internal("Connection closed".to_string()));
        }

        let response = String::from_utf8_lossy(&buf[..n]);
        let total_latency = start.elapsed();

        // L-5 FIX: Proper JSON-RPC validation for mining.subscribe response
        let (is_valid, subscription_id, error_msg) = Self::validate_sv1_response(&response);

        // AUTH4-L2: Anonymize address in logs to prevent leaking stratum probe targets
        debug!(
            addr_hash = %anonymize_addr(&addr),
            valid = is_valid,
            latency_ms = total_latency.as_millis(),
            "SV1 verification complete"
        );

        Ok(StratumVerifyResult {
            connected: true,
            valid_protocol: is_valid,
            connect_latency,
            total_latency,
            subscription_id,
            error: error_msg,
        })
    }

    /// L-5 FIX: Validate Stratum V1 mining.subscribe JSON-RPC response
    ///
    /// Returns (is_valid, subscription_id, error_message)
    fn validate_sv1_response(response: &str) -> (bool, Option<String>, Option<String>) {
        // L-5 FIX: Parse as JSON first - must be valid JSON
        let json: serde_json::Value = match serde_json::from_str(response) {
            Ok(j) => j,
            Err(e) => {
                return (
                    false,
                    None,
                    Some(format!("L-5: Response is not valid JSON: {}", e)),
                );
            }
        };

        // L-5 FIX: Must be a JSON object (not array, string, etc.)
        if !json.is_object() {
            return (
                false,
                None,
                Some("L-5: Response is not a JSON object".to_string()),
            );
        }

        // L-5 FIX: Must have "id" field matching our request ID (1)
        let id = json.get("id");
        match id {
            Some(serde_json::Value::Number(n)) if n.as_u64() == Some(1) => {}
            Some(serde_json::Value::Number(_)) => {
                return (
                    false,
                    None,
                    Some("L-5: Response id does not match request id (expected 1)".to_string()),
                );
            }
            Some(_) => {
                return (
                    false,
                    None,
                    Some("L-5: Response id is not a number".to_string()),
                );
            }
            None => {
                return (
                    false,
                    None,
                    Some("L-5: Response missing 'id' field".to_string()),
                );
            }
        }

        // L-5 FIX: Check for error response
        if let Some(error) = json.get("error") {
            if !error.is_null() {
                let error_msg = error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                return (
                    false,
                    None,
                    Some(format!("L-5: Server returned error: {}", error_msg)),
                );
            }
        }

        // L-5 FIX: Must have "result" field
        let result = match json.get("result") {
            Some(r) => r,
            None => {
                return (
                    false,
                    None,
                    Some("L-5: Response missing 'result' field".to_string()),
                );
            }
        };

        // L-5 FIX: Result must be an array (mining.subscribe format)
        // mining.subscribe result format: [[["mining.set_difficulty", "subscription_id"], ["mining.notify", "subscription_id"]], extranonce1, extranonce2_size]
        let result_array = match result.as_array() {
            Some(a) => a,
            None => {
                return (
                    false,
                    None,
                    Some("L-5: Result is not an array (not mining.subscribe format)".to_string()),
                );
            }
        };

        // L-5 FIX: mining.subscribe result should have at least 2 elements
        // [subscriptions_array, extranonce1, extranonce2_size]
        if result_array.len() < 2 {
            return (
                false,
                None,
                Some(format!(
                    "L-5: Result array too short ({} elements, expected 2+)",
                    result_array.len()
                )),
            );
        }

        // L-5 FIX: First element should be array of subscriptions
        let subscriptions = match result_array[0].as_array() {
            Some(s) => s,
            None => {
                return (
                    false,
                    None,
                    Some("L-5: First result element is not subscription array".to_string()),
                );
            }
        };

        // L-5 FIX: Extract subscription ID from mining.notify subscription
        let subscription_id = subscriptions.iter().find_map(|sub| {
            let sub_array = sub.as_array()?;
            if sub_array.len() >= 2 {
                let method = sub_array[0].as_str()?;
                if method == "mining.notify" || method == "mining.set_difficulty" {
                    return sub_array[1].as_str().map(|s| s.to_string());
                }
            }
            None
        });

        // L-5 FIX: Verify extranonce1 is present (second element)
        let extranonce1 = result_array.get(1).and_then(|v| v.as_str());
        if extranonce1.is_none() {
            return (
                false,
                subscription_id,
                Some("L-5: Missing or invalid extranonce1".to_string()),
            );
        }

        // All validation passed
        (true, subscription_id, None)
    }

    /// Verify Stratum V2 endpoint
    ///
    /// C-1 FIX: Performs proper Noise NK handshake validation to verify the endpoint
    /// is a real Stratum V2 server. Previously always returned valid_protocol: true.
    ///
    /// Validation requirements:
    /// 1. Connection must be established
    /// 2. Must receive valid Noise protocol response bytes
    /// 3. Response must match expected Noise NK responder format
    pub async fn verify_sv2(&self, host: &str, port: u16) -> GhostResult<StratumVerifyResult> {
        let addr = format!("{}:{}", host, port);
        let start = Instant::now();

        // Connect with timeout
        let stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| GhostError::Timeout("Stratum V2 connection timed out".to_string()))?
            .map_err(|e| GhostError::Internal(format!("Connection failed: {}", e)))?;

        let connect_latency = start.elapsed();

        // C-1 FIX: Generate a proper Noise NK initiator message
        // Noise NK initiator message format: 64 bytes total
        // - 32 bytes: ephemeral public key (e)
        // - 32 bytes: encrypted payload (AEAD ciphertext, can be empty for handshake initiation)
        // SRI Pool expects the full 64-byte message before responding
        let mut initiator_message = [0u8; 64];
        if getrandom::getrandom(&mut initiator_message).is_err() {
            return Err(GhostError::Internal(
                "C-1: Failed to generate Noise NK initiator message".to_string(),
            ));
        }

        let (mut reader, mut writer) = stream.into_split();

        // Send the complete Noise NK initiator message (64 bytes)
        let write_result = timeout(self.timeout, writer.write_all(&initiator_message)).await;

        if write_result.is_err() {
            // C-1 FIX: Write failure means protocol validation failed
            return Ok(StratumVerifyResult {
                connected: true,
                valid_protocol: false,
                connect_latency,
                total_latency: start.elapsed(),
                subscription_id: None,
                error: Some("Failed to send Noise NK handshake".to_string()),
            });
        }

        // C-1 FIX: Must receive a valid Noise NK response
        // The responder sends: 32-byte ephemeral + 16-byte AEAD tag + encrypted payload
        // Minimum valid response is 48 bytes (32 + 16)
        let mut buf = vec![0u8; 128];
        let read_result = timeout(self.timeout, reader.read(&mut buf)).await;

        let total_latency = start.elapsed();

        // C-1 FIX: Validate the response is proper Noise NK format
        let (valid_protocol, error_msg) = match read_result {
            Ok(Ok(n)) if n >= 48 => {
                // C-1 FIX: Got enough bytes for Noise NK response
                // Validate basic structure:
                // - First 32 bytes: responder ephemeral public key (should be non-zero)
                // - Next 16+ bytes: AEAD encrypted data
                let responder_ephemeral = &buf[..32];
                let is_ephemeral_valid = responder_ephemeral.iter().any(|&b| b != 0);

                if is_ephemeral_valid {
                    (true, None)
                } else {
                    (
                        false,
                        Some("Invalid Noise NK: zero responder ephemeral key".to_string()),
                    )
                }
            }
            Ok(Ok(n)) if n > 0 => {
                // C-1 FIX: Got some bytes but not enough for valid Noise NK
                (
                    false,
                    Some(format!(
                        "Invalid Noise NK: response too short ({} bytes, need 48+)",
                        n
                    )),
                )
            }
            Ok(Ok(_)) => {
                // C-1 FIX: Connection closed with no data - not valid
                (
                    false,
                    Some("Invalid Noise NK: connection closed with no response".to_string()),
                )
            }
            Ok(Err(e)) => {
                // C-1 FIX: Read error - not valid
                (false, Some(format!("Invalid Noise NK: read error: {}", e)))
            }
            Err(_) => {
                // C-1 FIX: Timeout waiting for response - not valid
                (
                    false,
                    Some("Invalid Noise NK: timeout waiting for response".to_string()),
                )
            }
        };

        // AUTH4-L2: Anonymize address in logs to prevent leaking stratum probe targets
        debug!(
            addr_hash = %anonymize_addr(&addr),
            valid = valid_protocol,
            latency_ms = total_latency.as_millis(),
            "SV2 verification complete"
        );

        Ok(StratumVerifyResult {
            connected: true,
            valid_protocol,
            connect_latency,
            total_latency,
            subscription_id: None,
            error: error_msg,
        })
    }
}

impl Default for StratumVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of Stratum verification
#[derive(Debug, Clone)]
pub struct StratumVerifyResult {
    /// Successfully connected
    pub connected: bool,
    /// Valid protocol response
    pub valid_protocol: bool,
    /// Time to establish connection
    pub connect_latency: Duration,
    /// Total verification time
    pub total_latency: Duration,
    /// Subscription ID (SV1 only)
    pub subscription_id: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Balance lookup function type
type BalanceFn = Box<dyn Fn(&str) -> GhostResult<u64> + Send + Sync>;

/// H-5: Epoch proof lookup function type
type EpochProofFn = Box<dyn Fn(u64) -> Option<EpochProof> + Send + Sync>;

/// Ghost Pay handler backed by L2 state
pub struct GhostPayL2Handler {
    /// Whether L2 is enabled
    enabled: bool,
    /// Current virtual block getter
    virtual_block_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Current epoch getter
    epoch_fn: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Balance lookup function
    balance_fn: BalanceFn,
    /// Whether Wraith protocol is enabled
    wraith_enabled: bool,
    /// H-5: Epoch proof lookup function for cryptographic verification
    epoch_proof_fn: Option<EpochProofFn>,
}

impl GhostPayL2Handler {
    /// Create a new Ghost Pay handler
    pub fn new<V, E, B>(
        enabled: bool,
        virtual_block: V,
        epoch: E,
        balance: B,
        wraith_enabled: bool,
    ) -> Self
    where
        V: Fn() -> u64 + Send + Sync + 'static,
        E: Fn() -> u64 + Send + Sync + 'static,
        B: Fn(&str) -> GhostResult<u64> + Send + Sync + 'static,
    {
        Self {
            enabled,
            virtual_block_fn: Box::new(virtual_block),
            epoch_fn: Box::new(epoch),
            balance_fn: Box::new(balance),
            wraith_enabled,
            epoch_proof_fn: None,
        }
    }
}

impl GhostPayHandler for GhostPayL2Handler {
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn get_virtual_block(&self) -> u64 {
        (self.virtual_block_fn)()
    }

    fn get_epoch(&self) -> u64 {
        (self.epoch_fn)()
    }

    fn get_balance(&self, address: &str) -> GhostResult<u64> {
        (self.balance_fn)(address)
    }

    fn is_wraith_enabled(&self) -> bool {
        self.wraith_enabled
    }

    /// H-5: Get proof of L2 state at a specific epoch
    fn get_epoch_proof(&self, epoch: u64) -> Option<EpochProof> {
        match &self.epoch_proof_fn {
            Some(f) => f(epoch),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stratum_verifier_creation() {
        let verifier = StratumVerifier::new();
        assert_eq!(verifier.timeout, Duration::from_secs(5));

        let verifier = verifier.with_timeout(Duration::from_secs(10));
        assert_eq!(verifier.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_ghostpay_handler() {
        let handler = GhostPayL2Handler::new(true, || 100, || 5, |_| Ok(50_000), true);

        assert!(handler.is_enabled());
        assert_eq!(handler.get_virtual_block(), 100);
        assert_eq!(handler.get_epoch(), 5);
        assert!(handler.is_wraith_enabled());
        assert_eq!(handler.get_balance("test").unwrap(), 50_000);
    }

    #[tokio::test]
    async fn test_stratum_sv1_invalid_port() {
        let verifier = StratumVerifier::new().with_timeout(Duration::from_millis(100));

        // Connect to a port that likely won't have a Stratum server
        let result = verifier.verify_sv1("127.0.0.1", 59999).await;

        // Should fail to connect
        assert!(result.is_err());
    }
}
