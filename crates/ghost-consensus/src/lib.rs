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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Consensus - P2P Mesh and BFT Voting
//!
//! This crate provides the consensus layer for Bitcoin Ghost:
//!
//! - **P2P Mesh**: ZMQ PUB/SUB for discovery/health, Noise-encrypted TCP for sensitive traffic
//! - **Peer Discovery**: Gossip-based peer discovery
//! - **Share Propagation**: Distribute shares across nodes
//! - **Block Announcements**: Notify peers of block found events
//! - **BFT Voting**: 67% threshold Byzantine fault-tolerant voting
//! - **Payout Consensus**: Pre-consensus on coinbase before mining
//! - **Health Monitoring**: Peer health pings and liveness
//!
//! Discovery and health pings use ZMQ PUB/SUB; sensitive messages (shares, blocks,
//! votes, payouts) go over point-to-point Noise-encrypted TCP (see `mesh` / `noise_pool`).

#![deny(unreachable_pub)]

pub mod ban_manager;
pub mod discovery_handler;
pub mod epoch;
#[cfg(feature = "zk-consensus")]
pub mod epoch_manager;
pub mod health_handler;
pub mod mesh;
pub mod message;
pub mod message_validator;
pub mod noise;
pub mod noise_fragment;
pub mod noise_pool;
#[cfg(feature = "zk-consensus")]
pub mod nullifier_route_handler;
pub mod peer;
pub mod reorg;
pub mod verification_handler;
pub mod vote_handler;
pub mod voting;

#[cfg(feature = "mpc-ceremony")]
pub mod mpc_handler;

pub use ban_manager::*;
pub use discovery_handler::*;
pub use epoch::*;
#[cfg(feature = "zk-consensus")]
pub use epoch_manager::*;
pub use health_handler::*;
pub use mesh::*;
pub use message::*;
pub use message_validator::*;
pub use noise::*;
pub use noise_pool::*;
#[cfg(feature = "zk-consensus")]
pub use nullifier_route_handler::*;
pub use peer::*;
pub use reorg::*;
pub use verification_handler::*;
pub use vote_handler::*;
pub use voting::*;

#[cfg(feature = "mpc-ceremony")]
pub use mpc_handler::*;
