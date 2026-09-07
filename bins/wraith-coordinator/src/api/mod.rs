//! HTTP endpoint handlers. One submodule per endpoint family so each
//! file stays focused on its own request/response contract.

pub mod blind_sig;
pub mod discover;
pub mod find_or_create;
pub mod gossip;
pub mod health;
pub mod lock_cosign;
pub mod round_tx;
pub mod session_inputs;
pub mod session_outputs;
pub mod session_status;
pub mod session_witness;
