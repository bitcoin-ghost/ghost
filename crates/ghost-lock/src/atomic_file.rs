//! Durable, atomic, race-safe file replacement.
//!
//! Re-exported from [`ghost_common::atomic_file`], which is the single
//! implementation. This module is the route the wallet crates take to it:
//! they all depend on `ghost-lock` already, and none of them depended on
//! `ghost-common`.
//!
//! There were briefly two copies of this code — one here and one in
//! `ghost-common` — because the wallet work and the consensus/MPC work landed
//! on separate branches and the crates could not reach each other. Two copies
//! of a durability primitive is exactly the shape of defect that produced them
//! in the first place: the fixed `.tmp` staging path was duplicated across
//! seven stores and every copy carried the same race.

pub use ghost_common::atomic_file::{staging_path, sync_parent_dir, write_atomic};
