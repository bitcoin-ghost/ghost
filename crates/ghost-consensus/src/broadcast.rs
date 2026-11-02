//! The canonical outbound-broadcast injection point.
//!
//! Enqueues an outbound broadcast `(msg_type, json_payload)`. Injected rather than referenced
//! directly so a handler does not depend on the mesh: `main.rs` wires a closure that pushes to the
//! broadcast task, and tests wire a closure that captures messages for in-process routing.
//!
//! This alias lives in its own module rather than in `vote_handler` deliberately. Broadcasting is
//! not a voting concern, and the subsystems that need it mostly do not vote.
//!
//! It is also declared, with an identical definition, in `payout_checkpoint` and `sbc_handler`.
//! Those duplicates are left where they are on purpose: they die with their modules, and editing a
//! module scheduled for deletion only adds conflict surface to the release that deletes it.

use std::sync::Arc;

use ghost_common::error::GhostResult;

use crate::message::MessageType;

/// Enqueues an outbound broadcast `(msg_type, json_payload)`.
pub type BroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;
