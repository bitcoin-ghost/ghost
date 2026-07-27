//! GhostGlyph — Visual Identity System
//!
//! Permanent 16x16 pixel ghost bitmaps bound to Ghost IDs.
//! Registration completes when a Ghost Lock is funded via Wraith deposit.

#![deny(unreachable_pub)]

pub mod error;
pub mod glyph;
pub mod palette;
pub mod render;

pub use error::GlyphError;
pub use glyph::{GhostGlyph, GLYPH_HEIGHT, GLYPH_SIZE, GLYPH_WIDTH, PALETTE_SIZE};
pub use palette::{palette_index_to_rgb, PALETTE};
pub use render::{render_rgba, rendered_dimensions, MAX_SCALE};
