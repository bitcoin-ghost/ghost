//! Wraith Wallet — core library.
//!
//! All wallet logic (keystore, modules, ghost-pay client, IPC server) lives here.
//! Binaries (`wraithd`, `wraith`) and the GUI shell are thin wrappers over this crate.

pub mod auth;
pub mod chain;
pub mod descriptor;
pub mod ghostd;
pub mod gsp;
pub mod keystore;
pub mod light;
pub mod lock_recovery;
pub mod mainnet_guard;
pub mod psbt;
pub mod signer;
pub mod user_entropy;
pub mod wraith;
pub mod wraith_signer;
