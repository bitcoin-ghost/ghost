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
//| FILE: noise.rs                                                                                                       |
//|======================================================================================================================|

//! Noise Protocol encryption for mesh network traffic
//!
//! Provides end-to-end encryption for P2P mesh communications using the
//! Noise Protocol Framework. This ensures:
//!
//! - **Confidentiality**: Traffic cannot be read by network observers
//! - **Authentication**: Peers verify each other's identities
//! - **Forward Secrecy**: Past sessions cannot be decrypted if keys leak
//! - **Identity Hiding**: Static keys not revealed until authenticated
//!
//! # Protocol Pattern
//!
//! Uses `Noise_XX_25519_ChaChaPoly_BLAKE2s`:
//! - XX: Mutual authentication with identity hiding
//! - X25519: ECDH key agreement
//! - ChaChaPoly: ChaCha20-Poly1305 AEAD cipher
//! - BLAKE2s: Fast hashing
//!
//! # Integration
//!
//! The `NoiseTransport` wraps a raw transport connection and provides
//! encrypted read/write operations. Use `NoiseSession` for the handshake.
//!
//! ```ignore
//! // Initiator side
//! let session = NoiseSession::initiator(&our_keys)?;
//! let encrypted_conn = session.handshake(raw_conn).await?;
//! encrypted_conn.send(message).await?;
//!
//! // Responder side
//! let session = NoiseSession::responder(&our_keys)?;
//! let encrypted_conn = session.handshake(raw_conn).await?;
//! let msg = encrypted_conn.recv().await?;
//! ```

use std::fmt;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use ghost_common::types::NodeId;

/// Noise protocol pattern used for mesh encryption
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum message size for Noise transport (64KB)
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Overhead bytes added by Noise encryption (AEAD tag)
pub const NOISE_OVERHEAD: usize = 16;

/// Maximum payload that can be encrypted in one message
pub const MAX_PAYLOAD_SIZE: usize = MAX_MESSAGE_SIZE - NOISE_OVERHEAD;

/// Noise protocol errors
///
/// # L-5 Security: Generic Error Messages for Peers
///
/// The `Display` implementation on these variants is designed for internal
/// logging only. When communicating errors to remote peers (e.g., over the
/// wire), always use `NoiseError::peer_message()` which returns a generic
/// string that does not leak internal state, handshake progress, or
/// library-specific error details.
#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("Handshake failed: {0}")]
    Handshake(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Message too large: {0} > {MAX_PAYLOAD_SIZE}")]
    MessageTooLarge(usize),

    #[error("Invalid peer identity")]
    InvalidPeerIdentity,

    #[error("Session not established")]
    NotEstablished,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Snow error: {0}")]
    Snow(#[from] snow::Error),
}

impl NoiseError {
    /// L-5: Return a generic error message safe to send to remote peers.
    ///
    /// This prevents leaking internal state such as handshake stage,
    /// library error details, or message sizes to potential attackers.
    /// Detailed error information is available via the `Display` or
    /// `Debug` traits for internal logging.
    pub fn peer_message(&self) -> &'static str {
        match self {
            NoiseError::Handshake(_) => "handshake failed",
            NoiseError::Encryption(_) => "encryption error",
            NoiseError::Decryption(_) => "decryption error",
            NoiseError::MessageTooLarge(_) => "message rejected",
            NoiseError::InvalidPeerIdentity => "authentication failed",
            NoiseError::NotEstablished => "session error",
            NoiseError::Io(_) => "connection error",
            NoiseError::Snow(_) => "protocol error",
        }
    }
}

/// Noise keypair for node identity
pub struct NoiseKeypair {
    /// Static private key (32 bytes) -- zeroized on drop
    private_key: [u8; 32],
    /// Static public key (32 bytes)
    public_key: [u8; 32],
}

// C-05: Manual Clone so we can have a manual Drop that zeroizes the private key.
impl Clone for NoiseKeypair {
    fn clone(&self) -> Self {
        Self {
            private_key: self.private_key,
            public_key: self.public_key,
        }
    }
}

// C-05: Zeroize private key material when NoiseKeypair is dropped.
impl Drop for NoiseKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl NoiseKeypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let builder = Builder::new(
            NOISE_PATTERN
                .parse()
                .expect("L-1: NOISE_PATTERN constant is valid"),
        );
        let keypair = builder
            .generate_keypair()
            .expect("L-1: Noise keypair generation should not fail");

        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        private_key.copy_from_slice(&keypair.private);
        public_key.copy_from_slice(&keypair.public);

        Self {
            private_key,
            public_key,
        }
    }

    /// Create from existing private key bytes
    ///
    /// CRIT-9: Properly derives the X25519 public key from the private key
    /// using scalar multiplication. The keypair is deterministic from the
    /// private key, ensuring peer authentication works after restart.
    pub fn from_private_key(private_key: [u8; 32]) -> Result<Self, NoiseError> {
        // CRIT-9: Use x25519-dalek for proper public key derivation
        // This ensures the keypair is deterministic from the private key
        use x25519_dalek::{PublicKey, StaticSecret};

        // Create the static secret from the private key bytes
        let secret = StaticSecret::from(private_key);

        // Derive the public key through scalar multiplication
        let public = PublicKey::from(&secret);

        let public_key: [u8; 32] = *public.as_bytes();

        // M-6 FIX: Do not log any key material, even partial public key fragments.
        // The existence of the derivation is sufficient for debugging purposes.
        debug!("Derived X25519 public key from private key bytes");

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Create from hex-encoded private key
    pub fn from_hex(hex_key: &str) -> Result<Self, NoiseError> {
        let bytes = hex::decode(hex_key)
            .map_err(|e| NoiseError::Handshake(format!("Invalid hex key: {}", e)))?;

        if bytes.len() != 32 {
            return Err(NoiseError::Handshake(format!(
                "Invalid key length: {} (expected 32)",
                bytes.len()
            )));
        }

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&bytes);

        Self::from_private_key(private_key)
    }

    /// Get public key bytes
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get public key as hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key)
    }

    /// Get private key bytes for internal crate use only.
    ///
    /// M-7 SECURITY: This method is restricted to pub(crate) to prevent external
    /// access to secret key material. Use only for keypair persistence operations.
    pub(crate) fn private_key(&self) -> &[u8; 32] {
        &self.private_key
    }

    /// Derive a NodeId from the Noise public key
    ///
    /// Note: This creates a separate identity from the Ed25519 node identity.
    /// For full integration, you'd want to use the same key material.
    pub fn as_node_id(&self) -> NodeId {
        self.public_key
    }
}

impl fmt::Debug for NoiseKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseKeypair")
            .field("public_key", &hex::encode(&self.public_key[..8]))
            .field("private_key", &"[redacted]")
            .finish()
    }
}

/// Configuration for Noise encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoiseConfig {
    /// Enable Noise encryption
    pub enabled: bool,
    /// Require Noise for all connections (reject unencrypted)
    pub required: bool,
    /// Path to persistent keypair file
    pub keypair_file: Option<String>,
    /// List of trusted peer public keys (hex encoded)
    /// If non-empty, only these peers can connect
    pub trusted_peers: Vec<String>,
    /// Allow connections from unknown peers
    pub allow_unknown_peers: bool,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: true,
            keypair_file: None,
            trusted_peers: Vec::new(),
            allow_unknown_peers: false,
        }
    }
}

/// Noise session state for handshake
pub struct NoiseSession {
    /// Our static keypair
    keypair: NoiseKeypair,
    /// Whether we're the initiator
    is_initiator: bool,
    /// Handshake state
    handshake: Option<HandshakeState>,
    /// Peer's static public key (known after handshake)
    #[allow(dead_code)]
    peer_public_key: Option<[u8; 32]>,
}

impl NoiseSession {
    /// Create a new initiator session (client connecting to server)
    pub fn initiator(keypair: &NoiseKeypair) -> Result<Self, NoiseError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?).local_private_key(&keypair.private_key);

        let handshake = builder.build_initiator()?;

        Ok(Self {
            keypair: keypair.clone(),
            is_initiator: true,
            handshake: Some(handshake),
            peer_public_key: None,
        })
    }

    /// Create a new responder session (server accepting connection)
    pub fn responder(keypair: &NoiseKeypair) -> Result<Self, NoiseError> {
        let builder = Builder::new(NOISE_PATTERN.parse()?).local_private_key(&keypair.private_key);

        let handshake = builder.build_responder()?;

        Ok(Self {
            keypair: keypair.clone(),
            is_initiator: false,
            handshake: Some(handshake),
            peer_public_key: None,
        })
    }

    /// B-2: Maximum time allowed for the Noise handshake before aborting.
    const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// Perform the Noise XX handshake over a connection
    ///
    /// Returns an encrypted transport on success.
    /// B-2: Times out after 10 seconds to prevent stalled handshake DoS.
    pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        self,
        stream: S,
    ) -> Result<(NoiseTransport<S>, [u8; 32]), NoiseError> {
        tokio::time::timeout(Self::HANDSHAKE_TIMEOUT, self.handshake_inner(stream))
            .await
            .map_err(|_| {
                NoiseError::Handshake("B-2: Handshake timed out after 10 seconds".into())
            })?
    }

    async fn handshake_inner<S: AsyncRead + AsyncWrite + Unpin>(
        mut self,
        mut stream: S,
    ) -> Result<(NoiseTransport<S>, [u8; 32]), NoiseError> {
        let mut handshake = self
            .handshake
            .take()
            .ok_or_else(|| NoiseError::Handshake("Session already used".into()))?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let mut read_buf = vec![0u8; MAX_MESSAGE_SIZE];

        // XX pattern has 3 messages:
        // -> e
        // <- e, ee, s, es
        // -> s, se

        if self.is_initiator {
            // Message 1: -> e (initiator sends ephemeral)
            let len = handshake.write_message(&[], &mut buf)?;
            send_message(&mut stream, &buf[..len]).await?;
            debug!("Noise: sent message 1 (-> e)");

            // Message 2: <- e, ee, s, es (responder replies)
            let msg = recv_message(&mut stream, &mut read_buf).await?;
            handshake.read_message(&msg, &mut buf)?;
            debug!("Noise: received message 2 (<- e, ee, s, es)");

            // Message 3: -> s, se (initiator authenticates)
            let len = handshake.write_message(&[], &mut buf)?;
            send_message(&mut stream, &buf[..len]).await?;
            debug!("Noise: sent message 3 (-> s, se)");
        } else {
            // Message 1: <- e (receive initiator's ephemeral)
            let msg = recv_message(&mut stream, &mut read_buf).await?;
            handshake.read_message(&msg, &mut buf)?;
            debug!("Noise: received message 1 (<- e)");

            // Message 2: -> e, ee, s, es (send our response)
            let len = handshake.write_message(&[], &mut buf)?;
            send_message(&mut stream, &buf[..len]).await?;
            debug!("Noise: sent message 2 (-> e, ee, s, es)");

            // Message 3: <- s, se (receive initiator's auth)
            let msg = recv_message(&mut stream, &mut read_buf).await?;
            handshake.read_message(&msg, &mut buf)?;
            debug!("Noise: received message 3 (<- s, se)");
        }

        // Get peer's static public key
        let peer_public_key = handshake
            .get_remote_static()
            .ok_or_else(|| NoiseError::Handshake("No remote static key".into()))?;

        let mut peer_key = [0u8; 32];
        peer_key.copy_from_slice(peer_public_key);

        debug!(
            peer = %hex::encode(&peer_key[..8]),
            "Noise handshake complete"
        );

        // Transition to transport mode
        let transport = handshake.into_transport_mode()?;

        Ok((
            NoiseTransport {
                stream,
                transport: Arc::new(Mutex::new(transport)),
                peer_public_key: peer_key,
                our_public_key: self.keypair.public_key,
            },
            peer_key,
        ))
    }

    /// Get our public key
    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }
}

/// Encrypted transport wrapper
pub struct NoiseTransport<S> {
    /// Underlying stream
    stream: S,
    /// Noise transport state (for encryption/decryption)
    transport: Arc<Mutex<TransportState>>,
    /// Peer's static public key
    peer_public_key: [u8; 32],
    /// Our static public key
    our_public_key: [u8; 32],
}

impl<S> NoiseTransport<S> {
    /// Get peer's public key
    pub fn peer_public_key(&self) -> &[u8; 32] {
        &self.peer_public_key
    }

    /// Get peer's public key as NodeId
    pub fn peer_node_id(&self) -> NodeId {
        self.peer_public_key
    }

    /// Get our public key
    pub fn our_public_key(&self) -> &[u8; 32] {
        &self.our_public_key
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseTransport<S> {
    /// Send an encrypted message
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), NoiseError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(NoiseError::MessageTooLarge(payload.len()));
        }

        let mut buf = vec![0u8; payload.len() + NOISE_OVERHEAD];

        let len = {
            let mut transport = self.transport.lock();
            transport.write_message(payload, &mut buf)?
        };

        send_message(&mut self.stream, &buf[..len]).await?;
        Ok(())
    }

    /// Receive and decrypt a message
    pub async fn recv(&mut self) -> Result<Vec<u8>, NoiseError> {
        let mut read_buf = vec![0u8; MAX_MESSAGE_SIZE];
        let ciphertext = recv_message(&mut self.stream, &mut read_buf).await?;

        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = {
            let mut transport = self.transport.lock();
            transport.read_message(&ciphertext, &mut plaintext)?
        };

        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Send multiple messages efficiently (batch encryption)
    pub async fn send_batch(&mut self, messages: &[&[u8]]) -> Result<(), NoiseError> {
        for msg in messages {
            self.send(msg).await?;
        }
        Ok(())
    }

    /// Get the underlying stream (for advanced use)
    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// Helper to send a length-prefixed message
async fn send_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<(), NoiseError> {
    // Send 2-byte length prefix (big-endian)
    let len = data.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Helper to receive a length-prefixed message
async fn recv_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
) -> Result<Vec<u8>, NoiseError> {
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;

    if len > buf.len() {
        return Err(NoiseError::MessageTooLarge(len));
    }

    stream.read_exact(&mut buf[..len]).await?;
    Ok(buf[..len].to_vec())
}

/// Manager for Noise-encrypted connections
pub struct NoiseManager {
    /// Our keypair
    keypair: NoiseKeypair,
    /// Configuration
    config: NoiseConfig,
    /// Trusted peer public keys
    trusted_peers: Vec<[u8; 32]>,
}

impl NoiseManager {
    /// Create a new Noise manager
    pub fn new(config: NoiseConfig) -> Result<Self, NoiseError> {
        let keypair = if let Some(ref path) = config.keypair_file {
            // Try to load from file
            match std::fs::read_to_string(path) {
                Ok(hex) => NoiseKeypair::from_hex(hex.trim())?,
                Err(e) => {
                    warn!("Failed to load Noise keypair from {}: {}", path, e);
                    // Generate new keypair
                    let kp = NoiseKeypair::generate();
                    // M-8 FIX: Save the PRIVATE key hex, not public key hex.
                    // from_hex() expects a private key to derive the keypair from.
                    if let Err(e) = std::fs::write(path, hex::encode(kp.private_key())) {
                        warn!("Failed to save Noise keypair: {}", e);
                    } else {
                        // H-08: Set restrictive permissions on keypair file (contains private key)
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Err(e) = std::fs::set_permissions(
                                path,
                                std::fs::Permissions::from_mode(0o600),
                            ) {
                                warn!("Failed to set keypair file permissions: {}", e);
                            }
                        }
                    }
                    kp
                }
            }
        } else {
            NoiseKeypair::generate()
        };

        // Parse trusted peers
        let trusted_peers: Vec<[u8; 32]> = config
            .trusted_peers
            .iter()
            .filter_map(|hex| {
                let bytes = hex::decode(hex).ok()?;
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
            .collect();

        info!(
            public_key = %keypair.public_key_hex(),
            trusted_peers = trusted_peers.len(),
            "Noise manager initialized"
        );

        Ok(Self {
            keypair,
            config,
            trusted_peers,
        })
    }

    /// Get our public key
    pub fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    /// Get our public key as hex
    pub fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// Check if a peer is trusted
    pub fn is_peer_trusted(&self, peer_key: &[u8; 32]) -> bool {
        if self.trusted_peers.is_empty() {
            // No trusted list = allow all (if allow_unknown_peers is true)
            self.config.allow_unknown_peers
        } else {
            self.trusted_peers.iter().any(|k| k == peer_key)
        }
    }

    /// Create an initiator session
    pub fn create_initiator(&self) -> Result<NoiseSession, NoiseError> {
        NoiseSession::initiator(&self.keypair)
    }

    /// Create a responder session
    pub fn create_responder(&self) -> Result<NoiseSession, NoiseError> {
        NoiseSession::responder(&self.keypair)
    }

    /// Wrap a connection with Noise encryption (initiator)
    pub async fn wrap_initiator<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<(NoiseTransport<S>, [u8; 32]), NoiseError> {
        let session = self.create_initiator()?;
        let (transport, peer_key) = session.handshake(stream).await?;

        // Check if peer is trusted
        if !self.is_peer_trusted(&peer_key) {
            return Err(NoiseError::InvalidPeerIdentity);
        }

        Ok((transport, peer_key))
    }

    /// Wrap a connection with Noise encryption (responder)
    pub async fn wrap_responder<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<(NoiseTransport<S>, [u8; 32]), NoiseError> {
        let session = self.create_responder()?;
        let (transport, peer_key) = session.handshake(stream).await?;

        // Check if peer is trusted
        if !self.is_peer_trusted(&peer_key) {
            return Err(NoiseError::InvalidPeerIdentity);
        }

        Ok((transport, peer_key))
    }

    /// Check if Noise is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if Noise is required (reject unencrypted connections)
    pub fn is_required(&self) -> bool {
        self.config.required
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn test_keypair_generation() {
        let kp1 = NoiseKeypair::generate();
        let kp2 = NoiseKeypair::generate();

        // Keys should be different
        assert_ne!(kp1.public_key(), kp2.public_key());

        // Keys should be 32 bytes
        assert_eq!(kp1.public_key().len(), 32);
        assert_eq!(kp1.private_key().len(), 32);
    }

    #[test]
    fn test_keypair_hex() {
        let kp = NoiseKeypair::generate();
        let hex = kp.public_key_hex();

        // Should be 64 hex chars (32 bytes)
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_noise_config_default() {
        let config = NoiseConfig::default();
        // B-1: Secure defaults — Noise required, unknown peers rejected
        assert!(config.enabled);
        assert!(config.required);
        assert!(!config.allow_unknown_peers);
        assert!(config.trusted_peers.is_empty());
    }

    #[tokio::test]
    async fn test_noise_handshake() {
        let initiator_keys = NoiseKeypair::generate();
        let responder_keys = NoiseKeypair::generate();

        // Save keys for verification before moving
        let expected_responder_key = *responder_keys.public_key();
        let expected_initiator_key = *initiator_keys.public_key();

        // Create duplex streams (like a TCP connection)
        let (client_stream, server_stream) = duplex(65536);

        // Spawn responder task
        let responder_handle = tokio::spawn(async move {
            let session = NoiseSession::responder(&responder_keys).unwrap();
            session.handshake(server_stream).await
        });

        // Run initiator
        let session = NoiseSession::initiator(&initiator_keys).unwrap();
        let (mut client_transport, peer_key) = session.handshake(client_stream).await.unwrap();

        // Wait for responder
        let (mut server_transport, client_key) = responder_handle.await.unwrap().unwrap();

        // Verify peer keys match
        assert_eq!(peer_key, expected_responder_key);
        assert_eq!(client_key, expected_initiator_key);

        // Test encrypted messaging
        let message = b"Hello, encrypted world!";
        client_transport.send(message).await.unwrap();

        let received = server_transport.recv().await.unwrap();
        assert_eq!(received, message);

        // Test bidirectional
        let reply = b"Message received!";
        server_transport.send(reply).await.unwrap();

        let received_reply = client_transport.recv().await.unwrap();
        assert_eq!(received_reply, reply);
    }

    #[tokio::test]
    async fn test_noise_manager() {
        let config = NoiseConfig::default();
        let manager = NoiseManager::new(config).unwrap();

        assert!(manager.is_enabled());
        assert!(manager.is_required());
        assert_eq!(manager.public_key().len(), 32);
    }

    #[tokio::test]
    async fn test_noise_manager_handshake() {
        // Tests use allow_unknown_peers since there's no pre-shared trusted key list
        let config1 = NoiseConfig {
            allow_unknown_peers: true,
            ..NoiseConfig::default()
        };
        let config2 = NoiseConfig {
            allow_unknown_peers: true,
            ..NoiseConfig::default()
        };

        let manager1 = NoiseManager::new(config1).unwrap();
        let manager2 = NoiseManager::new(config2).unwrap();

        // Save keys before moving managers
        let expected_manager2_key = *manager2.public_key();
        let expected_manager1_key = *manager1.public_key();

        let (stream1, stream2) = duplex(65536);

        // Manager 2 acts as responder
        let responder_handle = tokio::spawn(async move { manager2.wrap_responder(stream2).await });

        // Manager 1 acts as initiator
        let (mut transport1, peer_key) = manager1.wrap_initiator(stream1).await.unwrap();
        let (mut transport2, client_key) = responder_handle.await.unwrap().unwrap();

        // Verify keys
        assert_eq!(peer_key, expected_manager2_key);
        assert_eq!(client_key, expected_manager1_key);

        // Test communication
        transport1.send(b"test").await.unwrap();
        assert_eq!(transport2.recv().await.unwrap(), b"test");
    }

    #[test]
    fn test_trusted_peers() {
        let trusted_key = NoiseKeypair::generate();
        let untrusted_key = NoiseKeypair::generate();

        let config = NoiseConfig {
            enabled: true,
            required: false,
            keypair_file: None,
            trusted_peers: vec![trusted_key.public_key_hex()],
            allow_unknown_peers: false,
        };

        let manager = NoiseManager::new(config).unwrap();

        assert!(manager.is_peer_trusted(trusted_key.public_key()));
        assert!(!manager.is_peer_trusted(untrusted_key.public_key()));
    }

    #[test]
    fn test_message_size_limit() {
        // MAX_PAYLOAD_SIZE should allow encryption overhead
        assert!(MAX_PAYLOAD_SIZE < MAX_MESSAGE_SIZE);
        assert_eq!(
            MAX_PAYLOAD_SIZE + NOISE_OVERHEAD,
            MAX_MESSAGE_SIZE - NOISE_OVERHEAD + NOISE_OVERHEAD
        );
    }

    #[tokio::test]
    async fn test_b2_handshake_timeout() {
        use tokio::io::duplex;

        let keys = NoiseKeypair::generate();
        let session = NoiseSession::initiator(&keys).unwrap();

        // Create a duplex stream but never respond — simulates stalled peer
        let (client_stream, _server_stream) = duplex(65536);

        let start = std::time::Instant::now();
        let result = session.handshake(client_stream).await;
        let elapsed = start.elapsed();

        match result {
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    err_msg.contains("timed out"),
                    "Expected timeout error, got: {}",
                    err_msg
                );
            }
            Ok(_) => panic!("Expected handshake to fail with timeout"),
        }
        // Should complete within ~10s (with some slack for CI)
        assert!(
            elapsed.as_secs() <= 15,
            "Timeout took too long: {:?}",
            elapsed
        );
    }

    // ==========================================================================
    // CRIT-9: Key Derivation Tests
    // ==========================================================================

    /// CRIT-9-TEST-1: Verify keypair is deterministic from private key
    #[test]
    fn test_crit9_keypair_deterministic_from_private_key() {
        // Generate a random private key
        let mut private_key = [0u8; 32];
        getrandom::getrandom(&mut private_key).unwrap();

        // Create keypair twice from the same private key
        let kp1 = NoiseKeypair::from_private_key(private_key).unwrap();
        let kp2 = NoiseKeypair::from_private_key(private_key).unwrap();

        // Public keys MUST be identical (deterministic derivation)
        assert_eq!(
            kp1.public_key(),
            kp2.public_key(),
            "CRIT-9: Same private key MUST produce same public key"
        );

        // Private keys should match what we provided
        assert_eq!(
            kp1.private_key(),
            &private_key,
            "Private key should be preserved"
        );
    }

    /// CRIT-9-TEST-2: Verify different private keys produce different public keys
    #[test]
    fn test_crit9_different_private_keys_produce_different_public_keys() {
        let private_key1 = [1u8; 32];
        let private_key2 = [2u8; 32];

        let kp1 = NoiseKeypair::from_private_key(private_key1).unwrap();
        let kp2 = NoiseKeypair::from_private_key(private_key2).unwrap();

        assert_ne!(
            kp1.public_key(),
            kp2.public_key(),
            "Different private keys must produce different public keys"
        );
    }

    /// CRIT-9-TEST-3: Verify from_hex uses the actual provided key
    #[test]
    fn test_crit9_from_hex_uses_provided_key() {
        // Create a known private key
        let private_key = [42u8; 32];
        let hex_key = hex::encode(private_key);

        // Load from hex
        let kp1 = NoiseKeypair::from_hex(&hex_key).unwrap();

        // Create directly from bytes
        let kp2 = NoiseKeypair::from_private_key(private_key).unwrap();

        // They must match
        assert_eq!(
            kp1.public_key(),
            kp2.public_key(),
            "CRIT-9: from_hex and from_private_key must produce same result"
        );
        assert_eq!(
            kp1.private_key(),
            kp2.private_key(),
            "CRIT-9: Private keys must match"
        );
    }

    /// CRIT-9-TEST-4: Verify keypair can be saved and restored with same identity
    #[test]
    fn test_crit9_keypair_persistence_identity() {
        // Simulate saving and loading a keypair
        let original = NoiseKeypair::generate();
        let saved_private_hex = hex::encode(original.private_key());

        // Simulate restart - load from saved hex
        let restored = NoiseKeypair::from_hex(&saved_private_hex).unwrap();

        // The restored keypair MUST have the same identity
        assert_eq!(
            original.public_key(),
            restored.public_key(),
            "CRIT-9: Restored keypair must have same public key (identity)"
        );
        assert_eq!(
            original.private_key(),
            restored.private_key(),
            "CRIT-9: Restored keypair must have same private key"
        );
    }

    /// CRIT-9-TEST-5: Verify handshake works with restored keypair
    #[tokio::test]
    async fn test_crit9_handshake_with_restored_keypair() {
        // Simulate a node that saves its keypair and restarts
        let original_initiator = NoiseKeypair::generate();
        let original_responder = NoiseKeypair::generate();

        // Save the keypairs (simulate persistence)
        let initiator_private_hex = hex::encode(original_initiator.private_key());
        let responder_private_hex = hex::encode(original_responder.private_key());

        // Simulate restart - restore keypairs
        let restored_initiator = NoiseKeypair::from_hex(&initiator_private_hex).unwrap();
        let restored_responder = NoiseKeypair::from_hex(&responder_private_hex).unwrap();

        // Verify public keys match (this is the CRIT-9 fix)
        assert_eq!(
            original_initiator.public_key(),
            restored_initiator.public_key(),
            "Restored initiator must have same identity"
        );
        assert_eq!(
            original_responder.public_key(),
            restored_responder.public_key(),
            "Restored responder must have same identity"
        );

        // Now verify handshake works with restored keypairs
        let (stream1, stream2) = duplex(65536);

        let expected_responder_key = *restored_responder.public_key();

        let responder_handle = tokio::spawn(async move {
            let session = NoiseSession::responder(&restored_responder).unwrap();
            session.handshake(stream2).await
        });

        let session = NoiseSession::initiator(&restored_initiator).unwrap();
        let (mut transport, peer_key) = session.handshake(stream1).await.unwrap();
        let (mut responder_transport, _) = responder_handle.await.unwrap().unwrap();

        // Verify we got the correct peer identity
        assert_eq!(
            peer_key, expected_responder_key,
            "CRIT-9: Handshake should identify peer correctly after restore"
        );

        // Verify encrypted communication works
        transport.send(b"crit9-test").await.unwrap();
        let received = responder_transport.recv().await.unwrap();
        assert_eq!(
            received, b"crit9-test",
            "Encrypted communication should work after keypair restore"
        );
    }

    /// Test send_batch sends messages in order and all are received
    #[tokio::test]
    async fn test_send_batch_ordering() {
        let initiator_keys = NoiseKeypair::generate();
        let responder_keys = NoiseKeypair::generate();

        let (client_stream, server_stream) = duplex(65536);

        let responder_handle = tokio::spawn(async move {
            let session = NoiseSession::responder(&responder_keys).unwrap();
            session.handshake(server_stream).await
        });

        let session = NoiseSession::initiator(&initiator_keys).unwrap();
        let (mut client_transport, _) = session.handshake(client_stream).await.unwrap();
        let (mut server_transport, _) = responder_handle.await.unwrap().unwrap();

        // Send 10 messages via send_batch
        let messages: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 32]).collect();
        let refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        client_transport.send_batch(&refs).await.unwrap();

        // Receive all 10 and verify order
        for i in 0u8..10 {
            let received = server_transport.recv().await.unwrap();
            assert_eq!(received, vec![i; 32], "Message {} should match", i);
        }
    }

    /// Test into_inner recovers the underlying stream for raw I/O
    #[tokio::test]
    async fn test_into_inner_recovers_stream() {
        let initiator_keys = NoiseKeypair::generate();
        let responder_keys = NoiseKeypair::generate();

        let (client_stream, server_stream) = duplex(65536);

        let responder_handle = tokio::spawn(async move {
            let session = NoiseSession::responder(&responder_keys).unwrap();
            session.handshake(server_stream).await
        });

        let session = NoiseSession::initiator(&initiator_keys).unwrap();
        let (client_transport, _) = session.handshake(client_stream).await.unwrap();
        let (server_transport, _) = responder_handle.await.unwrap().unwrap();

        // Recover raw streams
        let mut raw_client = client_transport.into_inner();
        let mut raw_server = server_transport.into_inner();

        // Raw writes should still work (unencrypted now)
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        raw_client.write_all(b"raw-data").await.unwrap();
        raw_client.flush().await.unwrap();

        let mut buf = [0u8; 8];
        raw_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"raw-data");
    }

    /// Test oversized message is rejected with MessageTooLarge
    #[tokio::test]
    async fn test_oversized_message_rejected() {
        let initiator_keys = NoiseKeypair::generate();
        let responder_keys = NoiseKeypair::generate();

        let (client_stream, server_stream) = duplex(131072);

        let responder_handle = tokio::spawn(async move {
            let session = NoiseSession::responder(&responder_keys).unwrap();
            session.handshake(server_stream).await
        });

        let session = NoiseSession::initiator(&initiator_keys).unwrap();
        let (mut client_transport, _) = session.handshake(client_stream).await.unwrap();
        let _ = responder_handle.await.unwrap().unwrap();

        // Try sending a message larger than MAX_PAYLOAD_SIZE
        let oversized = vec![0xAA; MAX_PAYLOAD_SIZE + 1];
        let result = client_transport.send(&oversized).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            NoiseError::MessageTooLarge(size) => {
                assert_eq!(size, MAX_PAYLOAD_SIZE + 1);
            }
            other => panic!("Expected MessageTooLarge, got: {:?}", other),
        }
    }

    /// Test that untrusted peer is rejected when trusted_peers list is set
    #[tokio::test]
    async fn test_untrusted_peer_rejected_with_trusted_list() {
        let trusted_key = NoiseKeypair::generate();
        let untrusted_key = NoiseKeypair::generate();

        // Manager only trusts trusted_key, not untrusted_key
        let config = NoiseConfig {
            enabled: true,
            required: true,
            keypair_file: None,
            trusted_peers: vec![trusted_key.public_key_hex()],
            allow_unknown_peers: false,
        };
        let manager = NoiseManager::new(config).unwrap();

        let (client_stream, server_stream) = duplex(65536);

        // Untrusted peer connects as initiator
        let untrusted_clone = untrusted_key.clone();
        let initiator_handle = tokio::spawn(async move {
            let session = NoiseSession::initiator(&untrusted_clone).unwrap();
            session.handshake(client_stream).await
        });

        // Manager acts as responder — should reject untrusted peer
        let result = manager.wrap_responder(server_stream).await;
        match result {
            Err(NoiseError::InvalidPeerIdentity) => {} // Expected
            Err(other) => panic!("Expected InvalidPeerIdentity, got: {:?}", other),
            Ok(_) => panic!("Expected error for untrusted peer"),
        }

        // Initiator side may succeed or fail depending on timing; just wait for it
        let _ = initiator_handle.await;
    }
}
