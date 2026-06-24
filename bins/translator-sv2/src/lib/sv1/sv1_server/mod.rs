use stratum_apps::stratum_core::sv1_api::{json_rpc, Message};

pub(super) mod channel;
mod difficulty_manager;
pub mod downstream_message_handler;
pub mod sv1_server;

use tracing::warn;

/// Delimiter used to separate original job ID from keepalive mutation counter.
/// Format: `{original_job_id}#{counter}`
const KEEPALIVE_JOB_ID_DELIMITER: char = '#';

/// Check if Sv1 message is mining.authorize
pub(super) fn is_mining_authorize(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.authorize"
    } else {
        false
    }
}

/// Check if Sv1 message is mining.subscribe
pub(super) fn is_mining_subscribe(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.subscribe"
    } else {
        false
    }
}

/// Check if Sv1 message is mining.configure (BIP310 version-rolling negotiation).
/// Stateless handshake message that needs an immediate response — must NOT be
/// queued behind channel-open or the miner deadlocks waiting for the configure
/// reply before sending subscribe/authorize.
pub(super) fn is_mining_configure(msg: &Message) -> bool {
    if let json_rpc::Message::StandardRequest(r) = &msg {
        r.method == "mining.configure"
    } else {
        false
    }
}

/// Extracts the worker-identifier portion of an SV1 `mining.authorize` username for use as the
/// per-downstream identity that flows into the Worker-Specific Hashrate Tracking TLV.
///
/// Public-pool convention is `<payout_address>.<worker_name>` (e.g.
/// `bc1qabc...xyz.bitaxe1`). The address part is too long for the 32-byte TLV cap and would
/// duplicate information already carried in the channel-level `user_identity` (which the
/// translator config sources from the operator's wallet). The worker part — the bit that
/// actually distinguishes one device from another behind the same wallet — is short and fits.
///
/// If the username has no `.` separator, the whole string is treated as the worker name and
/// returned. The caller still passes the result through [`tlv_compatible_username`] to enforce
/// the 32-byte ceiling for safety against pathological inputs.
pub(super) fn extract_worker_name(name: &str) -> &str {
    name.rsplit_once('.').map(|(_, w)| w).unwrap_or(name)
}

/// Truncates a string to [`MAX_USER_IDENTITY_BYTES`], respecting UTF-8 character boundaries.
///
/// If the input string exceeds the limit, it is truncated at the last valid UTF-8 character
/// boundary before or at [`MAX_USER_IDENTITY_BYTES`] and a warning is logged.
fn tlv_compatible_username(s: &str) -> &str {
    const MAX_USER_IDENTITY_BYTES: usize = 32;
    let len = s.len();

    if len <= MAX_USER_IDENTITY_BYTES {
        return s;
    }
    // Find the last valid UTF-8 char boundary at or before MAX_USER_IDENTITY_BYTES
    let mut end = MAX_USER_IDENTITY_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = &s[..end];
    warn!(
        "Username '{}' exceeds {} bytes ({} bytes), truncating to '{}'. \
         Consider using a shorter username for full visibility on the pool dashboard.",
        s, MAX_USER_IDENTITY_BYTES, len, truncated
    );
    truncated
}
