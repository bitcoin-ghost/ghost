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
//| FILE: fuzz_p2p_payloads.rs                                                                                           |
//|======================================================================================================================|

//! Fuzz target for all P2P message payload types
//!
//! The message envelope fuzzer tests envelope parsing, but the inner payloads
//! are deserialized separately from the payload bytes. This target exercises
//! all 30+ payload types that arrive over the untrusted P2P network.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ghost_consensus::message::*;

fuzz_target!(|data: &[u8]| {
    // Try deserializing as every P2P payload type — none should panic

    // Core consensus
    let _ = serde_json::from_slice::<PayoutProposalMessage>(data);
    let _ = serde_json::from_slice::<VoteMessage>(data);
    let _ = serde_json::from_slice::<ShareProofMessage>(data);

    // Health & discovery
    let _ = serde_json::from_slice::<HealthPingMessage>(data);
    let _ = serde_json::from_slice::<DiscoveryMessage>(data);
    let _ = serde_json::from_slice::<PeerInfo>(data);

    // Share convergence
    let _ = serde_json::from_slice::<ShareConvergenceMessage>(data);
    let _ = serde_json::from_slice::<ShareConvergenceResponse>(data);

    // Verification
    let _ = serde_json::from_slice::<VerificationResultMessage>(data);

    // Byzantine evidence
    let _ = serde_json::from_slice::<EquivocationProofMessage>(data);

    // MPC ceremony
    let _ = serde_json::from_slice::<MpcContributionMessage>(data);
    let _ = serde_json::from_slice::<MpcVerificationVoteMessage>(data);
    let _ = serde_json::from_slice::<MpcParametersRequestMessage>(data);
    let _ = serde_json::from_slice::<MpcParametersResponseMessage>(data);

    // L2 layer
    let _ = serde_json::from_slice::<L2ConfidentialTransferMessage>(data);
    let _ = serde_json::from_slice::<L2TransferConfirmationMessage>(data);
    let _ = serde_json::from_slice::<L2TransferBroadcastMessage>(data);
    let _ = serde_json::from_slice::<L2CheckpointBlockMessage>(data);
    let _ = serde_json::from_slice::<L2CheckpointVoteMessage>(data);
    let _ = serde_json::from_slice::<L2TreeSyncRequest>(data);
    let _ = serde_json::from_slice::<L2TreeSyncResponse>(data);

    // GhostGlyph
    let _ = serde_json::from_slice::<GhostGlyphClaimMessage>(data);
    let _ = serde_json::from_slice::<GhostGlyphRegisteredMessage>(data);
});
