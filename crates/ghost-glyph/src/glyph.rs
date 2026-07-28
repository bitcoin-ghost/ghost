//! Core GhostGlyph types — 16x16 pixel ghost bitmaps bound to Ghost IDs

use sha2::{Digest, Sha256};

use crate::error::GlyphError;

/// Glyph width in pixels
pub const GLYPH_WIDTH: usize = 16;
/// Glyph height in pixels
pub const GLYPH_HEIGHT: usize = 16;
/// Total pixel count (256 bytes, one byte per pixel)
pub const GLYPH_SIZE: usize = GLYPH_WIDTH * GLYPH_HEIGHT;
/// Number of colors in the palette
pub const PALETTE_SIZE: usize = 26;

/// Domain separator for commitment hash
const COMMITMENT_DOMAIN: &[u8] = b"GhostGlyph/v1";
/// Domain separator for bitmap uniqueness hash
const BITMAP_DOMAIN: &[u8] = b"GhostGlyphBitmap/v1";

/// A 16x16 ghost glyph — each byte is a palette index (0-25)
#[derive(Debug, Clone)]
pub struct GhostGlyph {
    /// 256 bytes, each in range 0..25
    pub pixels: [u8; GLYPH_SIZE],
    /// bech32m ghost1... address
    pub ghost_id: String,
    /// SHA256("GhostGlyph/v1" || pixels || ghost_id_bytes) — binding commitment
    pub commitment: [u8; 32],
    /// SHA256("GhostGlyphBitmap/v1" || pixels) — uniqueness key
    pub bitmap_hash: [u8; 32],
    /// Unix timestamp when lock was funded (None if pending)
    pub registered_at: Option<u64>,
    /// Wraith deposit txid that triggered registration (None if pending)
    pub funding_txid: Option<String>,
}

impl GhostGlyph {
    /// Create a new glyph from pixels and ghost ID.
    ///
    /// Validates all pixel values are in range 0..25 and computes
    /// the commitment and bitmap hashes.
    pub fn new(pixels: [u8; GLYPH_SIZE], ghost_id: String) -> Result<Self, GlyphError> {
        Self::validate_pixels(&pixels)?;

        let commitment = Self::compute_commitment(&pixels, ghost_id.as_bytes());
        let bitmap_hash = Self::compute_bitmap_hash(&pixels);

        Ok(Self {
            pixels,
            ghost_id,
            commitment,
            bitmap_hash,
            registered_at: None,
            funding_txid: None,
        })
    }

    /// Validate that all pixels are within the palette range (0..25).
    pub fn validate_pixels(pixels: &[u8; GLYPH_SIZE]) -> Result<(), GlyphError> {
        for (index, &value) in pixels.iter().enumerate() {
            if value >= PALETTE_SIZE as u8 {
                return Err(GlyphError::InvalidPixelValue { index, value });
            }
        }
        Ok(())
    }

    /// Validate a pixel slice (for use before converting to fixed array).
    pub fn validate_pixel_slice(pixels: &[u8]) -> Result<(), GlyphError> {
        if pixels.len() != GLYPH_SIZE {
            return Err(GlyphError::InvalidSize {
                expected: GLYPH_SIZE,
                got: pixels.len(),
            });
        }
        for (index, &value) in pixels.iter().enumerate() {
            if value >= PALETTE_SIZE as u8 {
                return Err(GlyphError::InvalidPixelValue { index, value });
            }
        }
        Ok(())
    }

    /// Compute the binding commitment: SHA256("GhostGlyph/v1" || pixels || ghost_id_bytes)
    pub fn compute_commitment(pixels: &[u8; GLYPH_SIZE], ghost_id_bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(COMMITMENT_DOMAIN);
        hasher.update(pixels);
        hasher.update(ghost_id_bytes);
        hasher.finalize().into()
    }

    /// Compute the bitmap uniqueness hash: SHA256("GhostGlyphBitmap/v1" || pixels)
    pub fn compute_bitmap_hash(pixels: &[u8; GLYPH_SIZE]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(BITMAP_DOMAIN);
        hasher.update(pixels);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pixels() -> [u8; GLYPH_SIZE] {
        let mut pixels = [0u8; GLYPH_SIZE];
        for (i, px) in pixels.iter_mut().enumerate() {
            *px = (i % PALETTE_SIZE) as u8;
        }
        pixels
    }

    #[test]
    fn test_glyph_creation() {
        let pixels = test_pixels();
        let glyph = GhostGlyph::new(pixels, "ghost1testid".to_string()).unwrap();

        assert_eq!(glyph.pixels, pixels);
        assert_eq!(glyph.ghost_id, "ghost1testid");
        assert!(glyph.registered_at.is_none());
        assert!(glyph.funding_txid.is_none());
        // Hashes should be non-zero
        assert_ne!(glyph.commitment, [0u8; 32]);
        assert_ne!(glyph.bitmap_hash, [0u8; 32]);
    }

    #[test]
    fn test_invalid_pixel_value() {
        let mut pixels = [0u8; GLYPH_SIZE];
        pixels[100] = 26; // Out of range
        let result = GhostGlyph::new(pixels, "ghost1testid".to_string());
        assert!(result.is_err());
        match result.unwrap_err() {
            GlyphError::InvalidPixelValue { index, value } => {
                assert_eq!(index, 100);
                assert_eq!(value, 26);
            }
            other => panic!("Expected InvalidPixelValue, got {:?}", other),
        }
    }

    #[test]
    fn test_invalid_size() {
        let pixels = vec![0u8; 100]; // Wrong size
        let result = GhostGlyph::validate_pixel_slice(&pixels);
        assert!(result.is_err());
        match result.unwrap_err() {
            GlyphError::InvalidSize { expected, got } => {
                assert_eq!(expected, GLYPH_SIZE);
                assert_eq!(got, 100);
            }
            other => panic!("Expected InvalidSize, got {:?}", other),
        }
    }

    #[test]
    fn test_bitmap_hash_deterministic() {
        let pixels = test_pixels();
        let hash1 = GhostGlyph::compute_bitmap_hash(&pixels);
        let hash2 = GhostGlyph::compute_bitmap_hash(&pixels);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_ghost_ids_same_pixels() {
        let pixels = test_pixels();
        let glyph_a = GhostGlyph::new(pixels, "ghost1alice".to_string()).unwrap();
        let glyph_b = GhostGlyph::new(pixels, "ghost1bob".to_string()).unwrap();

        // Same bitmap → same bitmap_hash
        assert_eq!(glyph_a.bitmap_hash, glyph_b.bitmap_hash);
        // Different ghost_id → different commitment
        assert_ne!(glyph_a.commitment, glyph_b.commitment);
    }

    #[test]
    fn test_all_zero_pixels_valid() {
        let pixels = [0u8; GLYPH_SIZE];
        let glyph = GhostGlyph::new(pixels, "ghost1zero".to_string());
        assert!(glyph.is_ok());
    }

    #[test]
    fn test_all_max_pixels_valid() {
        let pixels = [25u8; GLYPH_SIZE];
        let glyph = GhostGlyph::new(pixels, "ghost1max".to_string());
        assert!(glyph.is_ok());
    }

    #[test]
    fn test_pixel_value_255_rejected() {
        let mut pixels = [0u8; GLYPH_SIZE];
        pixels[0] = 255;
        let result = GhostGlyph::new(pixels, "ghost1bad".to_string());
        assert!(result.is_err());
    }
}
