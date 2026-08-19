//! GhostGlyph P2P handler
//!
//! Processes glyph claim and registration messages from the mesh network.
//! Claims are validated and stored; registrations complete pending claims.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_glyph::{GhostGlyph, GLYPH_SIZE};
use ghost_storage::Database;

use ghost_consensus::broadcast::BroadcastFn;
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{
    GhostGlyphClaimMessage, GhostGlyphRegisteredMessage, MessageEnvelope, MessageType,
};

/// Maximum ghost_id length (bech32m addresses are typically ~62-90 chars).
const MAX_GHOST_ID_LEN: usize = 128;

/// Maximum clock skew allowed for claim/registration timestamps (5 minutes).
const MAX_TIMESTAMP_SKEW_SECS: u64 = 300;

/// Validate ghost_id format: non-empty, max length, no control chars, starts with "ghost1".
fn validate_ghost_id(ghost_id: &str) -> Result<(), String> {
    if ghost_id.is_empty() {
        return Err("ghost_id cannot be empty".to_string());
    }
    if ghost_id.len() > MAX_GHOST_ID_LEN {
        return Err(format!(
            "ghost_id too long: {} (max {})",
            ghost_id.len(),
            MAX_GHOST_ID_LEN
        ));
    }
    if ghost_id.chars().any(|c| c.is_control()) {
        return Err("ghost_id contains control characters".to_string());
    }
    if !ghost_id.starts_with("ghost1") {
        return Err("ghost_id must start with 'ghost1'".to_string());
    }
    Ok(())
}

/// Validate funding_txid format: exactly 64 lowercase hex characters.
fn validate_funding_txid(txid: &str) -> Result<(), String> {
    if txid.len() != 64 {
        return Err(format!(
            "funding_txid must be 64 hex chars, got {}",
            txid.len()
        ));
    }
    if !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("funding_txid must be hexadecimal".to_string());
    }
    Ok(())
}

/// Validate timestamp is within a reasonable window of the current time.
fn validate_timestamp(ts: u64) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if ts > now + MAX_TIMESTAMP_SKEW_SECS {
        return Err(format!(
            "timestamp {} is too far in the future (now={})",
            ts, now
        ));
    }
    // Allow timestamps up to 24h in the past (claim may have been delayed in transit)
    if now > ts + 86400 {
        return Err(format!("timestamp {} is too old (now={})", ts, now));
    }
    Ok(())
}

/// Check if a storage error is a UNIQUE constraint violation.
fn is_unique_violation(err: &GhostError) -> bool {
    let msg = err.to_string();
    msg.contains("already") || msg.contains("UNIQUE")
}

/// Handler for GhostGlyph P2P messages
pub struct GlyphRegistrationHandler {
    db: Arc<Database>,
    broadcast_fn: RwLock<Option<BroadcastFn>>,
}

impl GlyphRegistrationHandler {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            broadcast_fn: RwLock::new(None),
        }
    }

    /// Set the broadcast function for relaying claims/registrations to mesh
    pub fn set_broadcast_fn(&self, f: BroadcastFn) {
        *self.broadcast_fn.write() = Some(f);
    }

    /// Relay a glyph claim from ghost-pay: validate, store locally, broadcast to mesh.
    /// Called via the localhost-only relay endpoint.
    pub fn relay_claim(&self, data: Vec<u8>) -> GhostResult<()> {
        let msg: GhostGlyphClaimMessage = serde_json::from_slice(&data).map_err(|e| {
            GhostError::Serialization(format!("Invalid GhostGlyphClaimMessage: {}", e))
        })?;

        // H-1: Validate ghost_id format
        validate_ghost_id(&msg.ghost_id)
            .map_err(|e| GhostError::Internal(format!("Invalid ghost_id: {}", e)))?;

        // M-1: Validate timestamp
        validate_timestamp(msg.timestamp)
            .map_err(|e| GhostError::Internal(format!("Invalid claim timestamp: {}", e)))?;

        // Validate pixel array
        if msg.pixels.len() != GLYPH_SIZE {
            return Err(GhostError::Internal(format!(
                "Invalid pixel array size: {} (expected {})",
                msg.pixels.len(),
                GLYPH_SIZE
            )));
        }

        let pixels: [u8; GLYPH_SIZE] = msg
            .pixels
            .as_slice()
            .try_into()
            .map_err(|_| GhostError::Internal("Invalid pixel array".to_string()))?;

        if GhostGlyph::validate_pixels(&pixels).is_err() {
            return Err(GhostError::Internal(
                "Pixel values out of range".to_string(),
            ));
        }

        // Verify commitment
        let expected_commitment = GhostGlyph::compute_commitment(&pixels, msg.ghost_id.as_bytes());
        if msg.commitment != expected_commitment {
            return Err(GhostError::Internal("Commitment mismatch".to_string()));
        }

        // Verify bitmap hash
        let expected_bitmap_hash = GhostGlyph::compute_bitmap_hash(&pixels);
        if msg.bitmap_hash != expected_bitmap_hash {
            return Err(GhostError::Internal("Bitmap hash mismatch".to_string()));
        }

        // Store locally, only broadcast on successful insert
        // M-2: Do NOT broadcast on UNIQUE violation — the original broadcast already reached the mesh
        match self.db.insert_glyph_claim(
            &msg.ghost_id,
            &msg.pixels,
            &msg.bitmap_hash,
            &msg.commitment,
            msg.timestamp,
        ) {
            Ok(()) => {
                if let Some(ref broadcast) = *self.broadcast_fn.read() {
                    if let Err(e) = broadcast(MessageType::GhostGlyphClaim, data) {
                        warn!(error = %e, "Failed to broadcast glyph claim to mesh");
                    }
                }
                info!(ghost_id = %msg.ghost_id, "Glyph claim relayed to mesh");
            }
            Err(e) => {
                if is_unique_violation(&e) {
                    debug!(ghost_id = %msg.ghost_id, "Glyph claim already stored (idempotent)");
                } else {
                    warn!(error = %e, ghost_id = %msg.ghost_id, "Failed to store glyph claim, not broadcasting");
                }
            }
        }

        Ok(())
    }

    /// Relay a glyph registration from ghost-pay: validate, store locally, broadcast to mesh.
    pub fn relay_registered(&self, data: Vec<u8>) -> GhostResult<()> {
        let msg: GhostGlyphRegisteredMessage = serde_json::from_slice(&data).map_err(|e| {
            GhostError::Serialization(format!("Invalid GhostGlyphRegisteredMessage: {}", e))
        })?;

        // H-1: Validate ghost_id format
        validate_ghost_id(&msg.ghost_id)
            .map_err(|e| GhostError::Internal(format!("Invalid ghost_id: {}", e)))?;

        // H-2: Validate funding_txid format
        validate_funding_txid(&msg.funding_txid)
            .map_err(|e| GhostError::Internal(format!("Invalid funding_txid: {}", e)))?;

        // M-1: Validate registration timestamp
        validate_timestamp(msg.registered_at)
            .map_err(|e| GhostError::Internal(format!("Invalid registration timestamp: {}", e)))?;

        // Validate that a pending claim exists before completing
        let record = match self.db.get_glyph_by_ghost_id(&msg.ghost_id) {
            Ok(Some(record)) => {
                if record.funding_txid.is_some() {
                    // Already registered — idempotent, still broadcast for other nodes
                    if let Some(ref broadcast) = *self.broadcast_fn.read() {
                        let _ = broadcast(MessageType::GhostGlyphRegistered, data);
                    }
                    return Ok(());
                }
                record
            }
            Ok(None) => {
                return Err(GhostError::Internal(
                    "No pending glyph claim found for this ghost_id".to_string(),
                ));
            }
            Err(e) => {
                return Err(GhostError::Database(e.to_string()));
            }
        };

        // M-4: Verify bitmap_hash matches the pending claim
        if msg.bitmap_hash != record.bitmap_hash {
            return Err(GhostError::Internal(
                "bitmap_hash does not match pending claim".to_string(),
            ));
        }

        // L-3: Return error on failure so HTTP caller knows to retry
        match self.db.complete_glyph_registration(
            &msg.ghost_id,
            &msg.funding_txid,
            msg.registered_at,
        ) {
            Ok(()) => {
                if let Some(ref broadcast) = *self.broadcast_fn.read() {
                    if let Err(e) = broadcast(MessageType::GhostGlyphRegistered, data) {
                        warn!(error = %e, "Failed to broadcast glyph registration to mesh");
                    }
                }
                info!(ghost_id = %msg.ghost_id, "Glyph registration relayed to mesh");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, ghost_id = %msg.ghost_id, "Failed to complete glyph registration, not broadcasting");
                Err(GhostError::Database(format!(
                    "Failed to complete glyph registration: {}",
                    e
                )))
            }
        }
    }

    async fn handle_claim(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: GhostGlyphClaimMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                warn!(error = %e, "Failed to deserialize GhostGlyphClaimMessage");
                GhostError::P2PMessage(e.to_string())
            })?;

        // H-1: Validate ghost_id format
        if let Err(e) = validate_ghost_id(&msg.ghost_id) {
            warn!(error = %e, "Rejecting glyph claim: invalid ghost_id");
            return Ok(());
        }

        // M-1: Validate timestamp
        if let Err(e) = validate_timestamp(msg.timestamp) {
            warn!(error = %e, "Rejecting glyph claim: invalid timestamp");
            return Ok(());
        }

        // Validate pixel array size
        if msg.pixels.len() != GLYPH_SIZE {
            warn!(
                got = msg.pixels.len(),
                expected = GLYPH_SIZE,
                "Rejecting glyph claim: invalid pixel array size"
            );
            return Ok(());
        }

        // Validate pixel values (all 0..25)
        let pixels: [u8; GLYPH_SIZE] = msg
            .pixels
            .as_slice()
            .try_into()
            .map_err(|_| GhostError::P2PMessage("Invalid pixel array".to_string()))?;

        if GhostGlyph::validate_pixels(&pixels).is_err() {
            warn!(ghost_id = %msg.ghost_id, "Rejecting glyph claim: pixel values out of range");
            return Ok(());
        }

        // Verify commitment matches
        let expected_commitment = GhostGlyph::compute_commitment(&pixels, msg.ghost_id.as_bytes());
        if msg.commitment != expected_commitment {
            warn!(ghost_id = %msg.ghost_id, "Rejecting glyph claim: commitment mismatch");
            return Ok(());
        }

        // Verify bitmap hash matches
        let expected_bitmap_hash = GhostGlyph::compute_bitmap_hash(&pixels);
        if msg.bitmap_hash != expected_bitmap_hash {
            warn!(ghost_id = %msg.ghost_id, "Rejecting glyph claim: bitmap_hash mismatch");
            return Ok(());
        }

        // L-2: Check bitmap not already taken (log DB errors instead of swallowing)
        match self.db.is_bitmap_available(&msg.bitmap_hash) {
            Ok(false) => {
                debug!(ghost_id = %msg.ghost_id, "Glyph claim rejected: bitmap already taken");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, ghost_id = %msg.ghost_id, "DB error checking bitmap availability, proceeding to INSERT");
            }
            Ok(true) => {}
        }

        // L-2: Check ghost_id not already claimed (log DB errors)
        match self.db.get_glyph_by_ghost_id(&msg.ghost_id) {
            Ok(Some(_)) => {
                debug!(ghost_id = %msg.ghost_id, "Glyph claim rejected: ghost_id already has a glyph");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, ghost_id = %msg.ghost_id, "DB error checking ghost_id, proceeding to INSERT");
            }
            Ok(None) => {}
        }

        // Insert pending claim — L-1: UNIQUE constraint is the real arbiter
        match self.db.insert_glyph_claim(
            &msg.ghost_id,
            &msg.pixels,
            &msg.bitmap_hash,
            &msg.commitment,
            msg.timestamp,
        ) {
            Ok(()) => {
                info!(ghost_id = %msg.ghost_id, "GhostGlyph claim accepted (pending funding)");
            }
            Err(e) => {
                if !is_unique_violation(&e) {
                    warn!(error = %e, ghost_id = %msg.ghost_id, "Failed to insert glyph claim");
                }
            }
        }

        Ok(())
    }

    async fn handle_registered(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: GhostGlyphRegisteredMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                warn!(error = %e, "Failed to deserialize GhostGlyphRegisteredMessage");
                GhostError::P2PMessage(e.to_string())
            })?;

        // H-1: Validate ghost_id format
        if let Err(e) = validate_ghost_id(&msg.ghost_id) {
            warn!(error = %e, "Rejecting glyph registration: invalid ghost_id");
            return Ok(());
        }

        // H-2: Validate funding_txid format
        if let Err(e) = validate_funding_txid(&msg.funding_txid) {
            warn!(error = %e, "Rejecting glyph registration: invalid funding_txid");
            return Ok(());
        }

        // M-1: Validate registration timestamp
        if let Err(e) = validate_timestamp(msg.registered_at) {
            warn!(error = %e, "Rejecting glyph registration: invalid timestamp");
            return Ok(());
        }

        // Verify ghost_id has a pending claim
        let record = match self.db.get_glyph_by_ghost_id(&msg.ghost_id) {
            Ok(Some(record)) => {
                if record.funding_txid.is_some() {
                    // Already registered, idempotent
                    return Ok(());
                }
                record
            }
            Ok(None) => {
                debug!(ghost_id = %msg.ghost_id, "Ignoring registration: no pending claim found");
                return Ok(());
            }
            Err(e) => {
                warn!(error = %e, ghost_id = %msg.ghost_id, "Failed to look up glyph claim");
                return Ok(());
            }
        };

        // M-4: Verify bitmap_hash matches the pending claim
        if msg.bitmap_hash != record.bitmap_hash {
            warn!(ghost_id = %msg.ghost_id, "Rejecting registration: bitmap_hash mismatch with pending claim");
            return Ok(());
        }

        // Complete registration
        match self.db.complete_glyph_registration(
            &msg.ghost_id,
            &msg.funding_txid,
            msg.registered_at,
        ) {
            Ok(()) => {
                info!(
                    ghost_id = %msg.ghost_id,
                    txid = %msg.funding_txid,
                    "GhostGlyph registration confirmed via P2P"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    ghost_id = %msg.ghost_id,
                    "Failed to complete glyph registration from P2P"
                );
            }
        }

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for GlyphRegistrationHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        match envelope.msg_type {
            MessageType::GhostGlyphClaim => self.handle_claim(&envelope).await?,
            MessageType::GhostGlyphRegistered => self.handle_registered(&envelope).await?,
            _ => {}
        }
        Ok(())
    }
}
