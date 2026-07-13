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
//| FILE: template_provider.rs                                                                                           |
//|======================================================================================================================|

//! Template Distribution Protocol (TDP) Server with Noise Encryption
//!
//! Implements the SV2 Template Distribution Protocol, allowing SRI pool to connect
//! and receive block templates from ghost-pool. Uses Noise NX protocol for encryption.
//!
//! ```text
//! Bitcoin Core → ghost-pool (TDP Server) → SRI Pool → SRI Translator → Miners
//! ```
//!
//! # Protocol Messages
//!
//! - `NewTemplate`: Sent when a new block template is available
//! - `SetNewPrevHash`: Sent immediately when a new block is found
//! - `CoinbaseOutputConstraints`: Received from pool to specify coinbase limits
//! - `SubmitSolution`: Received when pool finds a valid block
//!
//! # Security
//!
//! All connections use Noise NX handshake for encrypted, authenticated communication.
//! The server has a keypair (authority key) and clients verify the server's identity.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_channel::{unbounded, Sender};
use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

// Use types from stratum-apps (stratum-core) consistently to avoid version conflicts
use stratum_apps::network_helpers::noise_stream::NoiseTcpStream;
use stratum_apps::stratum_core::{
    binary_sv2::{Seq0255, Seq064K, B016M, B064K},
    codec_sv2::{HandshakeRole, StandardSv2Frame},
    common_messages_sv2::SetupConnectionSuccess,
    framing_sv2::framing::Frame,
    noise_sv2::Responder,
    parsers_sv2::{AnyMessage, TemplateDistribution},
    template_distribution_sv2::{
        CoinbaseOutputConstraints, NewTemplate, RequestTransactionDataError,
        RequestTransactionDataSuccess, SetNewPrevHash, SubmitSolution,
    },
};
use stratum_apps::utils::protocol_message_type::{protocol_message_type, MessageType};

use crate::template::{TemplateEvent, TemplateProcessor, WorkState};

// ============================================================================
// Type Aliases
// ============================================================================

/// The message type used for TDP communication
type Message = AnyMessage<'static>;

/// SV2 frame type
type Sv2Frame = StandardSv2Frame<Message>;

// ============================================================================
// Configuration
// ============================================================================

/// TDP Server configuration
#[derive(Debug, Clone)]
pub struct TdpConfig {
    /// Listen address
    pub listen_addr: String,
    /// Listen port (default: 8442)
    pub port: u16,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout (seconds)
    pub timeout_secs: u64,
    /// Certificate validity in seconds (for Noise handshake)
    pub cert_validity_secs: u64,
    /// Authority secret key (32 bytes)
    pub authority_secret_key: [u8; 32],
    /// Authority public key (derived from secret key)
    pub authority_public_key: [u8; 32],
}

impl TdpConfig {
    /// Create a new TDP config with the given secret key
    ///
    /// # Errors
    /// Returns an error if the secret key is invalid (all zeros or outside valid range)
    ///
    /// # L-26 Security Fix
    /// Uses proper error handling instead of expect() to prevent panics on invalid keys
    pub fn new(secret_key: [u8; 32]) -> Result<Self, secp256k1::Error> {
        // Derive public key from secret key
        // L-26: Return error instead of panicking on invalid key
        let secp = secp256k1::Secp256k1::new();
        let secret = secp256k1::SecretKey::from_slice(&secret_key)?;
        let (x_only, _parity) = secret.public_key(&secp).x_only_public_key();
        let public_key = x_only.serialize();

        Ok(Self {
            listen_addr: "0.0.0.0".into(),
            port: 8442,
            max_connections: 10,
            timeout_secs: 30,
            cert_validity_secs: 86400, // 24 hours
            authority_secret_key: secret_key,
            authority_public_key: public_key,
        })
    }

    /// Get the authority public key in base58 format (for SRI pool config)
    pub fn authority_pubkey_base58(&self) -> String {
        // Version prefix (1) + public key
        let mut output = [0u8; 34];
        output[0] = 1; // Version
        output[1] = 0; // Padding
        output[2..].copy_from_slice(&self.authority_public_key);
        bs58::encode(&output).with_check().into_string()
    }
}

// C-1 SECURITY FIX: Removed Default impl for TdpConfig
//
// RATIONALE: Default impl panicked on key generation failure, which could
// crash the pool in production. Production deployments MUST provide explicit
// TdpConfig with properly generated keys via TdpConfig::new().
//
// Available alternatives:
//   - TdpConfig::new(secret_key) - Production use with explicit key
//   - TdpConfig::try_default() - Fallible random key generation
//   - TdpConfig::new_for_testing() - Test-only, returns Option
//
// This is a BREAKING CHANGE - code using TdpConfig::default() must be updated.

/// Error type for TdpConfig creation failures
#[derive(Debug, Clone)]
pub enum TdpConfigError {
    /// Failed to generate random bytes for secret key
    RandomGeneration(String),
    /// Invalid secret key (e.g., all zeros or out of curve range)
    InvalidSecretKey(String),
}

impl std::fmt::Display for TdpConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TdpConfigError::RandomGeneration(e) => {
                write!(f, "Failed to generate random secret key: {}", e)
            }
            TdpConfigError::InvalidSecretKey(e) => {
                write!(f, "Invalid secret key: {}", e)
            }
        }
    }
}

impl std::error::Error for TdpConfigError {}

impl TdpConfig {
    /// Create a TdpConfig with a randomly generated secret key.
    ///
    /// # Security Note
    /// For production deployments, prefer using `TdpConfig::new()` with a secret key
    /// loaded from persistent storage. Random keys generated here will be different
    /// on each restart, breaking client authentication.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Random number generation fails (system entropy unavailable)
    /// - The generated key is invalid (statistically impossible but handled)
    pub fn try_default() -> Result<Self, TdpConfigError> {
        let mut secret_key = [0u8; 32];
        getrandom::getrandom(&mut secret_key)
            .map_err(|e| TdpConfigError::RandomGeneration(e.to_string()))?;
        Self::new(secret_key).map_err(|e| TdpConfigError::InvalidSecretKey(e.to_string()))
    }

    /// Create a TdpConfig for testing purposes only
    ///
    /// Returns None if key generation fails (should never happen in tests)
    /// Production code should use TdpConfig::new() with explicit keys.
    #[cfg(test)]
    pub fn new_for_testing() -> Option<Self> {
        Self::try_default().ok()
    }
}

// ============================================================================
// Client State
// ============================================================================

/// Connected TDP client (SRI Pool)
struct TdpClient {
    /// Client address (stored for logging/debugging)
    #[allow(dead_code)]
    addr: SocketAddr,
    /// Sender for outgoing frames
    frame_tx: Sender<Sv2Frame>,
    /// Whether setup connection is complete
    setup_complete: bool,
    /// Coinbase output constraints from client
    coinbase_constraints: Option<CoinbaseOutputConstraints>,
    /// Last template ID sent
    last_template_id: u64,
}

// ============================================================================
// Template Distribution Server
// ============================================================================

/// Template Distribution Protocol Server with Noise encryption
pub struct TemplateDistributionServer {
    /// Configuration
    config: TdpConfig,
    /// Template processor for work states
    template_processor: Arc<TemplateProcessor>,
    /// Connected clients
    clients: Arc<RwLock<HashMap<u64, TdpClient>>>,
    /// Next client ID
    next_client_id: Arc<std::sync::atomic::AtomicU64>,
    /// Template ID counter
    template_id_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl TemplateDistributionServer {
    /// Create a new TDP server
    pub fn new(
        config: TdpConfig,
        template_processor: Arc<TemplateProcessor>,
        _shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        info!(
            "TDP authority public key: {}",
            config.authority_pubkey_base58()
        );

        Self {
            config,
            template_processor,
            clients: Arc::new(RwLock::new(HashMap::new())),
            next_client_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            template_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Run the TDP server
    pub async fn run(self) -> anyhow::Result<()> {
        let addr: SocketAddr =
            format!("{}:{}", self.config.listen_addr, self.config.port).parse()?;

        let listener = TcpListener::bind(addr).await?;
        info!(
            "TDP server listening on {} (Template Distribution Protocol)",
            addr
        );

        let clients = Arc::clone(&self.clients);
        let template_id_counter = Arc::clone(&self.template_id_counter);

        // Spawn template broadcast task
        let clients_for_broadcast = Arc::clone(&clients);
        let template_id_for_broadcast = Arc::clone(&template_id_counter);
        let template_processor_for_broadcast = Arc::clone(&self.template_processor);
        let mut template_rx = self.template_processor.subscribe();

        tokio::spawn(async move {
            loop {
                match template_rx.recv().await {
                    Ok(event) => {
                        if let TemplateEvent::NewWork { job_id, height } = event {
                            debug!("TDP: New work event - job_id={}, height={}", job_id, height);

                            if let Some(work_state) =
                                template_processor_for_broadcast.current_work()
                            {
                                let template_id = template_id_for_broadcast
                                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                                // Store work state for later SubmitSolution lookup
                                template_processor_for_broadcast
                                    .store_work_state(template_id, work_state.clone());

                                if let Err(e) = broadcast_template(
                                    &clients_for_broadcast,
                                    &work_state,
                                    template_id,
                                )
                                .await
                                {
                                    warn!("Failed to broadcast template: {}", e);
                                }
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("TDP broadcast lagged by {} templates", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!("Template channel closed, stopping TDP broadcast");
                        break;
                    }
                }
            }
        });

        loop {
            match listener.accept().await {
                Ok((socket, peer_addr)) => {
                    let current_clients = self.clients.read().len();
                    if current_clients >= self.config.max_connections {
                        warn!("TDP connection limit reached, rejecting {}", peer_addr);
                        continue;
                    }

                    info!(
                        "New TDP client from {} ({}/{})",
                        peer_addr,
                        current_clients + 1,
                        self.config.max_connections
                    );

                    let client_id = self
                        .next_client_id
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    // Create Noise responder for this connection
                    let responder = match Responder::from_authority_kp(
                        &self.config.authority_public_key,
                        &self.config.authority_secret_key,
                        Duration::from_secs(self.config.cert_validity_secs),
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            error!("Failed to create Noise responder: {:?}", e);
                            continue;
                        }
                    };

                    // Perform Noise handshake. The 10s per-read timeout matches
                    // stratum-apps' NOISE_HANDSHAKE_TIMEOUT default (used by
                    // accept_noise_connection), so a stalled peer handshake can't
                    // hang the TDP responder.
                    let noise_stream = match NoiseTcpStream::<Message>::new(
                        socket,
                        HandshakeRole::Responder(responder),
                        Duration::from_secs(10),
                    )
                    .await
                    {
                        Ok(ns) => {
                            info!("Noise handshake completed with {}", peer_addr);
                            ns
                        }
                        Err(e) => {
                            error!("Noise handshake failed with {}: {:?}", peer_addr, e);
                            continue;
                        }
                    };

                    let clients = Arc::clone(&self.clients);
                    let template_processor = Arc::clone(&self.template_processor);
                    let template_id_counter = Arc::clone(&self.template_id_counter);

                    tokio::spawn(async move {
                        if let Err(e) = handle_tdp_client(
                            noise_stream,
                            peer_addr,
                            client_id,
                            clients,
                            template_processor,
                            template_id_counter,
                        )
                        .await
                        {
                            debug!("TDP client {} error: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept TDP connection: {}", e);
                }
            }
        }
    }
}

// ============================================================================
// Client Handler
// ============================================================================

/// Handle a single TDP client connection (after Noise handshake)
async fn handle_tdp_client(
    noise_stream: NoiseTcpStream<Message>,
    peer_addr: SocketAddr,
    client_id: u64,
    clients: Arc<RwLock<HashMap<u64, TdpClient>>>,
    template_processor: Arc<TemplateProcessor>,
    template_id_counter: Arc<std::sync::atomic::AtomicU64>,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = noise_stream.into_split();
    let (frame_tx, frame_rx) = unbounded::<Sv2Frame>();

    // Register client
    {
        let mut clients_guard = clients.write();
        clients_guard.insert(
            client_id,
            TdpClient {
                addr: peer_addr,
                frame_tx: frame_tx.clone(),
                setup_complete: false,
                coinbase_constraints: None,
                last_template_id: 0,
            },
        );
    }

    // Spawn writer task
    let writer_handle = tokio::spawn(async move {
        while let Ok(frame) = frame_rx.recv().await {
            if writer.write_frame(frame.into()).await.is_err() {
                break;
            }
        }
    });

    // Handle SetupConnection first
    debug!("Waiting for SetupConnection from {}", peer_addr);
    let frame = reader
        .read_frame()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read SetupConnection: {:?}", e))?;

    // Extract Sv2Frame from the Frame enum
    let setup_frame = match frame {
        Frame::Sv2(sv2_frame) => sv2_frame,
        Frame::HandShake(_) => {
            return Err(anyhow::anyhow!("Received unexpected handshake frame"));
        }
    };

    // Parse and validate SetupConnection
    let header = setup_frame
        .get_header()
        .ok_or_else(|| anyhow::anyhow!("Missing frame header"))?;

    debug!(
        "Received frame from {}: ext_type={}, msg_type={}",
        peer_addr,
        header.ext_type(),
        header.msg_type()
    );

    // Send SetupConnectionSuccess
    let success = SetupConnectionSuccess {
        used_version: 2,
        flags: 0,
    };
    let response_frame: Sv2Frame = AnyMessage::Common(success.into())
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to create SetupConnectionSuccess frame"))?;

    frame_tx
        .send(response_frame)
        .await
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    info!("TDP client {} setup complete", peer_addr);

    // Mark client as setup complete
    if let Some(client) = clients.write().get_mut(&client_id) {
        client.setup_complete = true;
    }

    // Send initial template if available
    if let Some(work_state) = template_processor.current_work() {
        let template_id = template_id_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // Store work state for later SubmitSolution lookup
        template_processor.store_work_state(template_id, work_state.clone());

        send_new_template(&frame_tx, &work_state, template_id).await?;
        send_set_new_prev_hash(&frame_tx, &work_state, template_id).await?;

        if let Some(client) = clients.write().get_mut(&client_id) {
            client.last_template_id = template_id;
        }
    }

    // Main read loop
    loop {
        match reader.read_frame().await {
            Ok(frame) => {
                // Extract Sv2Frame from Frame enum
                let mut sv2_frame = match frame {
                    Frame::Sv2(f) => f,
                    Frame::HandShake(_) => {
                        warn!("Received unexpected handshake frame from {}", peer_addr);
                        continue;
                    }
                };

                let header = match sv2_frame.get_header() {
                    Some(h) => h,
                    None => {
                        warn!("Received frame without header from {}", peer_addr);
                        continue;
                    }
                };

                let msg_type = protocol_message_type(header.ext_type(), header.msg_type());
                info!("Received {:?} from {}", msg_type, peer_addr);

                match msg_type {
                    MessageType::TemplateDistribution => {
                        // Parse as TemplateDistribution message
                        if let Ok(td_msg) =
                            TemplateDistribution::try_from((header.msg_type(), sv2_frame.payload()))
                        {
                            if let Err(e) = handle_template_distribution_message(
                                td_msg,
                                client_id,
                                &clients,
                                &template_processor,
                            )
                            .await
                            {
                                let msg = e.to_string();
                                if msg.contains("inconclusive") || msg.contains("duplicate") {
                                    info!("TDP block submission race from {}: {}", peer_addr, msg);
                                } else {
                                    warn!("Error handling TDP message from {}: {}", peer_addr, e);
                                }
                                // Continue processing — don't kill the connection
                            }
                        } else {
                            warn!(
                                "Failed to parse TemplateDistribution message from {}",
                                peer_addr
                            );
                        }
                    }
                    MessageType::Common => {
                        debug!("Received Common message from {} (ignoring)", peer_addr);
                    }
                    _ => {
                        warn!(
                            "Received unexpected message type {:?} from {}",
                            msg_type, peer_addr
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    "TDP read error from {} (connection lost): {:?}",
                    peer_addr, e
                );
                break;
            }
        }
    }

    // Cleanup
    writer_handle.abort();
    clients.write().remove(&client_id);

    info!("TDP client {} disconnected", peer_addr);
    Ok(())
}

/// Handle incoming TemplateDistribution messages
async fn handle_template_distribution_message(
    msg: TemplateDistribution<'_>,
    client_id: u64,
    clients: &Arc<RwLock<HashMap<u64, TdpClient>>>,
    template_processor: &Arc<TemplateProcessor>,
) -> anyhow::Result<()> {
    match msg {
        TemplateDistribution::CoinbaseOutputConstraints(constraints) => {
            info!(
                "Received CoinbaseOutputConstraints from client {}",
                client_id
            );
            // Store constraints for this client
            if let Some(client) = clients.write().get_mut(&client_id) {
                client.coinbase_constraints = Some(constraints);
            }
        }
        TemplateDistribution::RequestTransactionData(request) => {
            debug!(
                "Received RequestTransactionData for template {} from client {}",
                request.template_id, client_id
            );

            // Get the client's frame sender for responding
            let frame_tx = {
                let clients_guard = clients.read();
                clients_guard.get(&client_id).map(|c| c.frame_tx.clone())
            };

            let Some(frame_tx) = frame_tx else {
                warn!(
                    "Client {} not found when handling RequestTransactionData",
                    client_id
                );
                return Ok(());
            };

            // Look up the work state for the requested template
            match template_processor.get_work_state(request.template_id) {
                Some(work_state) => {
                    // Convert template transactions to SV2 format
                    // Each transaction is serialized as B016M (max 16MB per transaction)
                    let mut tx_list: Vec<B016M<'static>> =
                        Vec::with_capacity(work_state.template.transactions.len());

                    for tx in &work_state.template.transactions {
                        match hex::decode(&tx.data) {
                            Ok(tx_bytes) => {
                                match tx_bytes.try_into() {
                                    Ok(b016m) => tx_list.push(b016m),
                                    Err(_) => {
                                        // Transaction too large (>16MB), which should never happen
                                        warn!(
                                            "Transaction {} too large for B016M in template {}",
                                            tx.txid, request.template_id
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to decode transaction {} hex: {}", tx.txid, e);
                            }
                        }
                    }

                    // Create the success response
                    let transaction_list: Seq064K<'static, B016M<'static>> = match Seq064K::new(
                        tx_list,
                    ) {
                        Ok(seq) => seq,
                        Err(_) => {
                            // Too many transactions (shouldn't happen with valid blocks)
                            warn!(
                                "Too many transactions for Seq064K in template {}",
                                request.template_id
                            );
                            // Send error response
                            // M-10 SECURITY FIX: Use map_err to handle conversion failure gracefully
                            // instead of expect(). String to Str0255 conversion can fail if string
                            // exceeds 255 bytes, though "transaction-list-overflow" never will.
                            let error_code = match "transaction-list-overflow"
                                .to_string()
                                .try_into()
                            {
                                Ok(code) => code,
                                Err(_) => {
                                    warn!("M-10: Failed to create error code string - returning without response");
                                    return Ok(());
                                }
                            };
                            let error = RequestTransactionDataError {
                                template_id: request.template_id,
                                error_code,
                            };
                            let error_frame: Sv2Frame = AnyMessage::TemplateDistribution(
                                TemplateDistribution::RequestTransactionDataError(error)
                                    .into_static(),
                            )
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Failed to create error frame"))?;
                            // SEC-ERR-2: Log channel send failures
                            if let Err(e) = frame_tx.send(error_frame).await {
                                warn!(error = %e, "Failed to send transaction data error frame to client");
                            }
                            return Ok(());
                        }
                    };

                    // M-10 SECURITY FIX: Use match instead of expect()
                    // Empty vec conversion to B064K should always succeed, but handle gracefully
                    let excess_data: B064K<'static> = match Vec::new().try_into() {
                        Ok(v) => v,
                        Err(_) => {
                            warn!("M-10: Failed to create empty excess_data - returning without response");
                            return Ok(());
                        }
                    };

                    let success = RequestTransactionDataSuccess {
                        template_id: request.template_id,
                        transaction_list,
                        excess_data,
                    };

                    let success_frame: Sv2Frame = AnyMessage::TemplateDistribution(
                        TemplateDistribution::RequestTransactionDataSuccess(success).into_static(),
                    )
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to create success frame"))?;

                    if let Err(e) = frame_tx.send(success_frame).await {
                        warn!(
                            "Failed to send RequestTransactionDataSuccess to client {}: {:?}",
                            client_id, e
                        );
                    } else {
                        debug!(
                            "Sent RequestTransactionDataSuccess for template {} ({} transactions)",
                            request.template_id,
                            work_state.template.transactions.len()
                        );
                    }
                }
                None => {
                    // Template not found or expired
                    warn!(
                        "Template {} not found for RequestTransactionData from client {}",
                        request.template_id, client_id
                    );

                    // M-10 SECURITY FIX: Use match instead of expect()
                    let error_code = match "template-id-not-found".to_string().try_into() {
                        Ok(code) => code,
                        Err(_) => {
                            warn!("M-10: Failed to create error code string - returning without response");
                            return Ok(());
                        }
                    };
                    let error = RequestTransactionDataError {
                        template_id: request.template_id,
                        error_code,
                    };

                    let error_frame: Sv2Frame = AnyMessage::TemplateDistribution(
                        TemplateDistribution::RequestTransactionDataError(error).into_static(),
                    )
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to create error frame"))?;

                    if let Err(e) = frame_tx.send(error_frame).await {
                        warn!(
                            "Failed to send RequestTransactionDataError to client {}: {:?}",
                            client_id, e
                        );
                    }
                }
            }
        }
        TemplateDistribution::SubmitSolution(solution) => {
            info!(
                "Received SubmitSolution from client {} (template_id={})",
                client_id, solution.template_id
            );
            // This is the critical path - a valid block was found!
            handle_submit_solution(solution, template_processor).await?;
        }
        _ => {
            debug!(
                "Received other TemplateDistribution message from client {}",
                client_id
            );
        }
    }
    Ok(())
}

/// Handle a block solution submission
async fn handle_submit_solution(
    solution: SubmitSolution<'_>,
    template_processor: &Arc<TemplateProcessor>,
) -> anyhow::Result<()> {
    info!(
        "Block solution received: template_id={}, version=0x{:08x}, ntime={}, nonce=0x{:08x}",
        solution.template_id, solution.version, solution.header_timestamp, solution.header_nonce
    );

    // Get the work state for this specific template_id
    // This is critical - we must use the work state that was active when the miner
    // received the template, NOT the current work state which may have changed
    let work_state = template_processor
        .get_work_state(solution.template_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No work state found for template_id={} (template may have expired)",
                solution.template_id
            )
        })?;

    // Get the coinbase transaction from the solution
    let coinbase_tx: &[u8] = solution.coinbase_tx.inner_as_ref();
    if coinbase_tx.len() < 60 {
        return Err(anyhow::anyhow!(
            "Coinbase transaction too short: {} bytes",
            coinbase_tx.len()
        ));
    }

    // Check if coinbase is witness or non-witness format
    let is_witness = coinbase_tx.len() > 5 && coinbase_tx[4] == 0x00 && coinbase_tx[5] == 0x01;
    info!(
        "Submitting block at height {} with {} byte coinbase (witness={})",
        work_state.height,
        coinbase_tx.len(),
        is_witness
    );

    // Log first bytes of coinbase for debugging
    info!(
        "Coinbase first 20 bytes: {}",
        hex::encode(&coinbase_tx[..std::cmp::min(20, coinbase_tx.len())])
    );

    // Convert coinbase to non-witness format if needed (for TXID computation)
    let coinbase_non_witness = strip_witness_if_present(coinbase_tx)?;

    info!(
        "Non-witness coinbase: {} bytes, first 20: {}",
        coinbase_non_witness.len(),
        hex::encode(&coinbase_non_witness[..std::cmp::min(20, coinbase_non_witness.len())])
    );

    // Compute coinbase TXID using bitcoin crate (same as SRI does)
    // This ensures identical TXID computation
    let coinbase_tx_parsed: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&coinbase_non_witness)
            .map_err(|e| anyhow::anyhow!("Failed to parse coinbase: {}", e))?;
    let txid = coinbase_tx_parsed.compute_txid();
    let coinbase_txid: [u8; 32] = *txid.as_ref();
    info!("Coinbase TXID (bitcoin crate): {}", txid);

    // Compute merkle root from coinbase TXID and merkle branches
    info!(
        "Merkle branches count: {}",
        work_state.merkle_branches.len()
    );
    let merkle_root = compute_merkle_root(&coinbase_txid, &work_state.merkle_branches);
    info!("Computed merkle root: {}", hex::encode(merkle_root));

    // Build the 80-byte block header
    // Use the RPC display-format hash (not the Stratum word-reversed prev_hash)
    // because build_block_header converts to Bitcoin internal byte order.
    let header = build_block_header(
        solution.version,
        &work_state.template.previousblockhash,
        &merkle_root,
        solution.header_timestamp,
        &work_state.nbits,
        solution.header_nonce,
    )?;

    // Log full header for debugging
    info!("Block header (80 bytes): {}", hex::encode(header));
    // Compute block hash for verification
    let block_hash = double_sha256(&header);
    info!(
        "Block hash (should match SRI): {}",
        hex::encode(block_hash.iter().rev().copied().collect::<Vec<_>>())
    );

    // Submit the block to Bitcoin Core
    // Pass the ORIGINAL witness coinbase from SRI for block data,
    // and the non-witness version for weight calculation
    template_processor
        .submit_block_with_coinbase(coinbase_tx, &coinbase_non_witness, &header, &work_state)
        .await?;

    // Notify the payout task that this block has been submitted to Bitcoin Core.
    // block_hash from double_sha256 is in internal byte order; reverse to display order.
    let mut block_hash_display = block_hash;
    block_hash_display.reverse();
    template_processor.notify_block_submitted(crate::template::BlockSubmittedInfo {
        block_hash: block_hash_display,
        height: work_state.height,
        // The payout this block's coinbase actually pays — the snapshot the template was built
        // against, not whatever happens to be approved by the time the notification lands.
        payout_snapshot: work_state.payout_snapshot,
    });

    info!(
        "Block at height {} submitted successfully!",
        work_state.height
    );

    Ok(())
}

/// Strip witness data from a coinbase transaction if present
///
/// Witness format: version(4) | marker(0x00) | flag(0x01) | inputs | outputs | locktime | witness
/// Non-witness:    version(4) | inputs | outputs | locktime
fn strip_witness_if_present(coinbase: &[u8]) -> anyhow::Result<Vec<u8>> {
    if coinbase.len() < 10 {
        return Err(anyhow::anyhow!("Coinbase too short"));
    }

    // Check for witness marker/flag at bytes 4-5
    // Witness: marker=0x00, flag=0x01
    // Non-witness: input_count (0x01 for coinbase with 1 input)
    if coinbase[4] == 0x00 && coinbase[5] == 0x01 {
        // This is witness format - need to strip marker/flag and witness data
        debug!("Stripping witness data from coinbase");

        let mut non_witness = Vec::with_capacity(coinbase.len());

        // Copy version (bytes 0-3)
        non_witness.extend_from_slice(&coinbase[0..4]);

        // Skip marker/flag (bytes 4-5), copy the rest of the transaction
        // We need to find where the witness data starts (after locktime)
        // Parse the transaction to find the boundary

        // Input count starts at byte 6 (after marker/flag)
        let mut pos = 6;

        // Read input count (varint) - just parse, don't copy yet
        let (input_count, varint_len) = read_varint(&coinbase[pos..])?;
        pos += varint_len;

        // Skip inputs
        for _ in 0..input_count {
            // prev_txid (32) + prev_vout (4) = 36 bytes
            pos += 36;

            // scriptSig length (varint)
            let (script_len, varint_len) = read_varint(&coinbase[pos..])?;
            pos += varint_len;
            pos += script_len as usize; // scriptSig

            // sequence (4 bytes)
            pos += 4;
        }

        // Read output count (varint)
        let (output_count, varint_len) = read_varint(&coinbase[pos..])?;
        let _outputs_start = pos;
        pos += varint_len;

        // Skip outputs
        for _ in 0..output_count {
            // value (8 bytes)
            pos += 8;

            // scriptPubKey length (varint)
            let (script_len, varint_len) = read_varint(&coinbase[pos..])?;
            pos += varint_len;
            pos += script_len as usize; // scriptPubKey
        }

        // pos now points to WITNESS data (not locktime!)
        // In BIP141 format: version | marker | flag | inputs | outputs | WITNESS | locktime
        // We need to:
        // 1. Copy from input_count through end of outputs (bytes 6..pos)
        // 2. Skip witness data
        // 3. Copy locktime (last 4 bytes of the transaction)

        // Copy inputs and outputs (skipping marker/flag at bytes 4-5)
        non_witness.extend_from_slice(&coinbase[6..pos]);

        // Copy locktime (always the last 4 bytes)
        non_witness.extend_from_slice(&coinbase[coinbase.len() - 4..]);

        Ok(non_witness)
    } else {
        // Already non-witness format
        debug!("Coinbase already in non-witness format");
        Ok(coinbase.to_vec())
    }
}

/// Read a Bitcoin varint from a byte slice
/// Returns (value, bytes_consumed)
/// HIGH-PANIC-1: Use .get() and try_into() for safe byte access
fn read_varint(data: &[u8]) -> anyhow::Result<(u64, usize)> {
    let first = match data.first() {
        Some(&b) => b,
        None => return Err(anyhow::anyhow!("Empty data for varint")),
    };

    match first {
        0..=0xfc => Ok((first as u64, 1)),
        0xfd => {
            let bytes: [u8; 2] = data
                .get(1..3)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("Truncated varint (fd)"))?;
            Ok((u16::from_le_bytes(bytes) as u64, 3))
        }
        0xfe => {
            let bytes: [u8; 4] = data
                .get(1..5)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("Truncated varint (fe)"))?;
            Ok((u32::from_le_bytes(bytes) as u64, 5))
        }
        0xff => {
            let bytes: [u8; 8] = data
                .get(1..9)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("Truncated varint (ff)"))?;
            Ok((u64::from_le_bytes(bytes), 9))
        }
    }
}

/// Compute double SHA256 hash
fn double_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let first = Sha256::digest(data);
    let second = Sha256::digest(first);

    let mut result = [0u8; 32];
    result.copy_from_slice(&second);
    result
}

/// Compute merkle root from coinbase TXID and merkle branches
fn compute_merkle_root(coinbase_txid: &[u8; 32], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *coinbase_txid;

    for branch in branches {
        // Concatenate current hash with branch hash and double SHA256
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&current);
        combined[32..].copy_from_slice(branch);
        current = double_sha256(&combined);
    }

    current
}

/// Build an 80-byte block header
fn build_block_header(
    version: u32,
    prev_hash_hex: &str,
    merkle_root: &[u8; 32],
    timestamp: u32,
    nbits_hex: &str,
    nonce: u32,
) -> anyhow::Result<[u8; 80]> {
    let mut header = [0u8; 80];

    // Version (4 bytes, little-endian)
    header[0..4].copy_from_slice(&version.to_le_bytes());

    // Previous block hash (32 bytes)
    // Input is RPC display format (big-endian hex). Bitcoin block headers store
    // the prev_hash in internal byte order (full 32-byte reversal of display).
    let mut prev_hash_bytes =
        hex::decode(prev_hash_hex).map_err(|e| anyhow::anyhow!("Invalid prev_hash hex: {}", e))?;
    if prev_hash_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Invalid prev_hash length: {}",
            prev_hash_bytes.len()
        ));
    }
    prev_hash_bytes.reverse();
    header[4..36].copy_from_slice(&prev_hash_bytes);

    // Merkle root (32 bytes, already in internal byte order)
    header[36..68].copy_from_slice(merkle_root);

    // Timestamp (4 bytes, little-endian)
    header[68..72].copy_from_slice(&timestamp.to_le_bytes());

    // nBits (4 bytes, little-endian)
    let nbits = u32::from_str_radix(nbits_hex, 16)
        .map_err(|e| anyhow::anyhow!("Invalid nbits hex: {}", e))?;
    header[72..76].copy_from_slice(&nbits.to_le_bytes());

    // Nonce (4 bytes, little-endian)
    header[76..80].copy_from_slice(&nonce.to_le_bytes());

    Ok(header)
}

// ============================================================================
// Message Sending Helpers
// ============================================================================

/// Send a NewTemplate message
async fn send_new_template(
    frame_tx: &Sender<Sv2Frame>,
    work_state: &WorkState,
    template_id: u64,
) -> anyhow::Result<()> {
    let template = create_new_template(work_state, template_id)?;
    debug!(
        "Sending NewTemplate: id={}, height={}, future_template={}",
        template_id, work_state.height, template.future_template
    );

    let frame: Sv2Frame =
        AnyMessage::TemplateDistribution(TemplateDistribution::NewTemplate(template).into_static())
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to create frame"))?;

    frame_tx
        .send(frame)
        .await
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    Ok(())
}

/// Send a SetNewPrevHash message
async fn send_set_new_prev_hash(
    frame_tx: &Sender<Sv2Frame>,
    work_state: &WorkState,
    template_id: u64,
) -> anyhow::Result<()> {
    let prev_hash = create_set_new_prev_hash(work_state, template_id)?;
    debug!(
        "Sending SetNewPrevHash: template_id={}, ntime={}",
        template_id, prev_hash.header_timestamp
    );

    let frame: Sv2Frame = AnyMessage::TemplateDistribution(
        TemplateDistribution::SetNewPrevHash(prev_hash).into_static(),
    )
    .try_into()
    .map_err(|_| anyhow::anyhow!("Failed to create frame"))?;

    frame_tx
        .send(frame)
        .await
        .map_err(|_| anyhow::anyhow!("Channel closed"))?;

    Ok(())
}

/// Broadcast a new template to all connected clients
async fn broadcast_template(
    clients: &Arc<RwLock<HashMap<u64, TdpClient>>>,
    work_state: &WorkState,
    template_id: u64,
) -> anyhow::Result<()> {
    // Collect senders while holding lock, then release before sending
    let senders: Vec<(u64, Sender<Sv2Frame>, bool)> = {
        let clients_guard = clients.read();
        clients_guard
            .iter()
            .map(|(id, client)| (*id, client.frame_tx.clone(), client.setup_complete))
            .collect()
    };

    let mut sent_count = 0;
    for (client_id, frame_tx, setup_complete) in senders {
        if !setup_complete {
            continue; // Skip clients that haven't completed setup
        }

        if send_new_template(&frame_tx, work_state, template_id)
            .await
            .is_ok()
        {
            if send_set_new_prev_hash(&frame_tx, work_state, template_id)
                .await
                .is_ok()
            {
                sent_count += 1;
            }
        } else {
            debug!("Failed to send template to client {}", client_id);
        }
    }

    if sent_count > 0 {
        info!(
            "Broadcast template {} to {} TDP clients (height: {})",
            template_id, sent_count, work_state.height
        );
    }

    Ok(())
}

// ============================================================================
// Message Creation Helpers
// ============================================================================

/// Create a NewTemplate message from WorkState
fn create_new_template(
    work_state: &WorkState,
    template_id: u64,
) -> anyhow::Result<NewTemplate<'static>> {
    use stratum_apps::stratum_core::binary_sv2::{B0255, B064K, U256};

    // Extract just the scriptSig prefix from coinbase1
    // coinbase1 format: version(4) + input_count(1) + prev_txhash(32) + prev_outindex(4) + scriptsig_len(1) + scriptsig_data
    // SV2 protocol expects coinbase_prefix to carry the BIP34 height push only.
    //
    // IMPORTANT: we must NOT include the pool tag (config.coinbase_extra) in
    // the TDP coinbase_prefix, because SRI Pool's channels_sv2 independently
    // stamps the scriptSig with its own `pool_tag_string` via the
    // `/pool_tag_string//` delimiter injection in `JobFactory::coinbase`. The
    // tag flows from ghost-pool to sri-pool via the `coinbase_tag` file
    // (written at startup in main.rs) and the systemd ExecStartPre step,
    // so it still lands in the final scriptSig — but only once. Including it
    // here as well produces a double-stamp that bitaxe miners display as
    // "- G H O S T - X - G H O S T - X" in decoded block explorers.
    //
    // SRI will construct the full coinbase by:
    // - Adding its own version, marker/flag, input structure
    // - Using our coinbase_prefix as the leading scriptSig content (height only)
    // - Injecting its pool_tag_string as "/<tag>//" between coinbase_prefix and extranonce
    // - Adding extranonce
    // - Using our coinbase_tx_outputs
    const SCRIPTSIG_START: usize = 4 + 1 + 32 + 4 + 1; // 42 bytes before scriptSig data

    if work_state.coinbase1.len() < SCRIPTSIG_START {
        return Err(anyhow::anyhow!("Coinbase1 too short"));
    }

    // BIP34 encodes the block height as a 1-byte push opcode + N little-endian
    // bytes, where N depends on the height's magnitude. This matches the exact
    // encoding produced by `TemplateProcessor::encode_height`.
    let height = work_state.height;
    let height_push_len: usize = if height <= 0x7f {
        2 // OP_PUSH1 + 1 byte
    } else if height <= 0x7fff {
        3 // OP_PUSH2 + 2 bytes
    } else if height <= 0x7fffff {
        4 // OP_PUSH3 + 3 bytes
    } else {
        5 // OP_PUSH4 + 4 bytes
    };

    let scriptsig_full = &work_state.coinbase1[SCRIPTSIG_START..];
    if scriptsig_full.len() < height_push_len {
        return Err(anyhow::anyhow!(
            "Coinbase1 scriptSig shorter than expected BIP34 height push"
        ));
    }
    let scriptsig_prefix = &scriptsig_full[..height_push_len];

    debug!(
        "TDP coinbase_prefix: {} bytes (height-only, stripping {} tag bytes), hex: {}",
        scriptsig_prefix.len(),
        scriptsig_full.len() - height_push_len,
        hex::encode(scriptsig_prefix)
    );

    let coinbase_prefix: B0255<'static> = scriptsig_prefix
        .to_vec()
        .try_into()
        .map_err(|_| anyhow::anyhow!("ScriptSig prefix too long"))?;

    // Convert merkle branches to Seq0255<U256>
    let merkle_path: Vec<U256<'static>> = work_state
        .merkle_branches
        .iter()
        .map(|branch| U256::from(*branch))
        .collect();

    let merkle_path_seq: Seq0255<'static, U256<'static>> = merkle_path.into();

    // Use Ghost's pre-built coinbase outputs instead of letting SRI Pool add its own
    // This gives Ghost full control over payouts (BFT consensus, treasury, etc.)
    let coinbase_outputs: B064K<'static> = work_state
        .coinbase_outputs_serialized
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Coinbase outputs too long"))?;

    debug!(
        "TDP NewTemplate: outputs_count={}, outputs_len={}",
        work_state.coinbase_outputs_count,
        work_state.coinbase_outputs_serialized.len()
    );

    Ok(NewTemplate {
        template_id,
        future_template: true, // Must be true for SRI pool to register initial template
        version: work_state.version,
        coinbase_tx_version: 2, // Standard coinbase version
        coinbase_prefix,
        coinbase_tx_input_sequence: 0xffffffff,
        // Ghost-pool provides ALL coinbase outputs (payouts, treasury, OP_RETURN).
        // Set value_remaining to 0 so SRI does not add its own payout outputs.
        coinbase_tx_value_remaining: 0,
        coinbase_tx_outputs_count: work_state.coinbase_outputs_count,
        coinbase_tx_outputs: coinbase_outputs, // Ghost's outputs (BFT payouts, treasury)
        coinbase_tx_locktime: 0,
        merkle_path: merkle_path_seq,
    })
}

/// Create a SetNewPrevHash message from WorkState
fn create_set_new_prev_hash(
    work_state: &WorkState,
    template_id: u64,
) -> anyhow::Result<SetNewPrevHash<'static>> {
    use stratum_apps::stratum_core::binary_sv2::U256;

    // Parse prev_hash from RPC display format and convert to Bitcoin internal byte order
    // (full 32-byte reversal). SV2 U256 expects little-endian = internal byte order.
    let mut prev_hash_bytes = hex::decode(&work_state.template.previousblockhash)
        .map_err(|e| anyhow::anyhow!("Invalid prev_hash hex: {}", e))?;
    prev_hash_bytes.reverse();

    let prev_hash: U256<'static> = prev_hash_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid prev_hash length"))?;

    // Parse nbits from hex string
    let nbits = u32::from_str_radix(&work_state.nbits, 16)
        .map_err(|e| anyhow::anyhow!("Invalid nbits: {}", e))?;

    Ok(SetNewPrevHash {
        template_id,
        prev_hash,
        header_timestamp: work_state.ntime,
        n_bits: nbits,
        target: nbits_to_target_u256(nbits),
    })
}

/// Convert nBits compact format to U256 target
fn nbits_to_target_u256(nbits: u32) -> stratum_apps::stratum_core::binary_sv2::U256<'static> {
    use stratum_apps::stratum_core::binary_sv2::U256;

    let mut target = [0u8; 32];
    let exponent = ((nbits >> 24) & 0xff) as usize;
    let mantissa = nbits & 0x007fffff;

    if exponent <= 3 {
        let shift = 8 * (3 - exponent);
        let value = mantissa >> shift;
        target[0] = (value & 0xff) as u8;
        target[1] = ((value >> 8) & 0xff) as u8;
        target[2] = ((value >> 16) & 0xff) as u8;
    } else {
        let byte_offset = exponent - 3;
        if byte_offset < 32 {
            target[byte_offset] = (mantissa & 0xff) as u8;
            if byte_offset + 1 < 32 {
                target[byte_offset + 1] = ((mantissa >> 8) & 0xff) as u8;
            }
            if byte_offset + 2 < 32 {
                target[byte_offset + 2] = ((mantissa >> 16) & 0xff) as u8;
            }
        }
    }

    // M-10 SECURITY FIX: Use safe fallback instead of expect()
    // Convert target to U256, falling back to zero if conversion fails
    U256::try_from(target.to_vec()).unwrap_or_else(|_| {
        // 32-byte zero vec conversion is infallible, but handle gracefully
        match U256::try_from(vec![0u8; 32]) {
            Ok(v) => v,
            Err(_) => {
                // This should never happen, but return a valid zero U256
                // by using the From<[u8; 32]> impl which is infallible
                U256::from([0u8; 32])
            }
        }
    })
}

/// Get block subsidy for a given height
#[cfg(test)]
fn get_block_subsidy(height: u64) -> u64 {
    let halvings = height / 210_000;
    if halvings >= 64 {
        return 0;
    }
    // Initial subsidy: 50 BTC = 5_000_000_000 satoshis
    5_000_000_000u64 >> halvings
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tdp_config_try_default() {
        // C-1: try_default() should succeed when entropy is available
        let config = TdpConfig::try_default().expect("Key generation should succeed in tests");
        assert_eq!(config.port, 8442);
        assert_eq!(config.max_connections, 10);
        // Public key should be derivable
        assert!(!config.authority_pubkey_base58().is_empty());
    }

    #[test]
    fn test_tdp_config_new_for_testing() {
        // C-1: new_for_testing() wraps try_default() for convenience in tests
        let config = TdpConfig::new_for_testing().expect("Key generation should succeed in tests");
        assert_eq!(config.port, 8442);
        assert_eq!(config.max_connections, 10);
        // Public key should be derivable
        assert!(!config.authority_pubkey_base58().is_empty());
    }

    #[test]
    fn test_tdp_config_with_key() {
        let secret_key = [0x42u8; 32];
        let config = TdpConfig::new(secret_key).expect("Valid test key");
        // Should generate consistent public key
        let pubkey = config.authority_pubkey_base58();
        assert!(pubkey.starts_with("9")); // Base58 encoding starts with specific chars
    }

    #[test]
    fn test_tdp_config_rejects_zero_key() {
        // L-26: Zero key should be rejected
        let zero_key = [0u8; 32];
        let result = TdpConfig::new(zero_key);
        assert!(result.is_err(), "Zero key should be rejected");
    }

    #[test]
    fn test_block_subsidy() {
        assert_eq!(get_block_subsidy(0), 5_000_000_000);
        assert_eq!(get_block_subsidy(210_000), 2_500_000_000);
        assert_eq!(get_block_subsidy(420_000), 1_250_000_000);
    }
}
