//! Wraith Wallet — core library.
//!
//! All wallet logic (keystore, modules, ghost-pay client, IPC server) lives here.
//! Binaries (`wraithd`, `wraith`) and the GUI shell are thin wrappers over this crate.

pub mod auth;
pub mod block_scan;
pub mod candidate_scan;
pub mod chain;
pub mod descriptor;
pub mod detection_store;
pub mod ghost_lock_account;
pub mod ghost_lock_store;
pub mod ghostd;
pub mod history_store;
pub mod keystore;
pub mod light;
pub mod lock_cosign_client;
pub mod mainnet_guard;
pub mod psbt;
pub mod scan_state;
pub mod signer;
/// Re-exported: the implementation moved to `ghost-entropy` so the offline
/// signer can share it. Unchanged, tags included.
pub use ghost_entropy as user_entropy;
/// Re-exported: moved to `wraith-protocol` beside the trait it implements, so
/// the coordinator can use it without depending on the wallet.
pub use wraith_protocol::signing_ledger_file;
pub mod wraith;
pub mod wraith_signer;
