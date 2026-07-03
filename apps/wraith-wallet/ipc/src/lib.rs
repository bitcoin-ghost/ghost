//! Wraith Wallet — IPC types shared between `wraithd` and clients (CLI, GUI).
//!
//! Wire format: newline-delimited JSON-RPC 2.0. One request per line, one response per line.
//!
//! Methods are typed: each `Request::*` variant pairs with a `Response::*` variant of the same name.
//!
//! Trust model: the socket is bound at owner-only (0600) permissions, so the
//! channel is restricted to processes running as the same user as `wraithd`.
//! Passphrases travel in plaintext over the socket; do **not** log requests
//! verbatim. Phase 16 hardening tightens this surface.

use serde::{Deserialize, Serialize};

pub const JSONRPC_VERSION: &str = "2.0";

/// Default socket path discovery.
///
/// On Unix, in this order:
///   1. `WRAITHD_SOCKET` env var (explicit override — used by demos
///      and tests that want multiple instances on the same host)
///   2. `${XDG_RUNTIME_DIR}/wraithd-${UID}.sock`
///   3. `/tmp/wraithd-${UID}.sock` if XDG_RUNTIME_DIR is unset
#[cfg(unix)]
pub fn default_socket_path() -> std::path::PathBuf {
    use std::path::PathBuf;
    if let Some(explicit) = std::env::var_os("WRAITHD_SOCKET") {
        return PathBuf::from(explicit);
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    dir.join(format!("wraithd-{uid}.sock"))
}

/// Default upper bound on BIP86 indices to derive when scanning L1
/// UTXOs. 32 is small enough that even mainnet's scantxoutset
/// completes in a few seconds, and matches the typical address-gap
/// limit a wallet would have given out.
pub(crate) fn default_l1_scan_max_index() -> u32 {
    32
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Health,
    /// One-shot connectivity + health summary (daemon + ghost-pay + ghost-gsp + session).
    Doctor,
    ChainStatus,
    GspPing,
    /// Register the active wallet's auth identity with the configured GSP and create
    /// a session. Idempotent — already-registered wallets proceed straight to session.
    GspAuth,
    /// Inspect the daemon's stored GSP session token + persistent connection state.
    GspSessionStatus,
    /// Register the active wallet's BIP-352 scan public key with the GSP so the
    /// server can detect incoming silent payments on its behalf.
    GspRegisterScanKey,
    /// Read the active wallet's last-known on-chain balance from the persistent session.
    LightBalance,
    /// List the active wallet's UTXOs via the persistent GSP session.
    LightUtxos {
        /// Minimum number of confirmations. Default 1.
        min_confirmations: u32,
    },
    /// List unspent L1 outputs at the active wallet's BIP86 receive
    /// addresses. Daemon derives addresses 0..`scan_max_index` and
    /// asks ghost-pay to run `scantxoutset` against them.
    /// Authenticated against ghost-pay via the
    /// `WRAITHD_GHOST_PAY_INTERNAL_AUTH` shared secret. Returns
    /// each matching UTXO tagged with the BIP86 index that produced
    /// its address — drop straight into Wraith mix's `bip86_index`
    /// field to skip the daemon-side scan.
    LightL1Utxos {
        /// Highest BIP86 index to derive. Daemon scans 0..this.
        /// Capped server-side at 1024 (ghost-pay's scantxoutset
        /// limit).
        #[serde(default = "default_l1_scan_max_index")]
        scan_max_index: u32,
        /// Minimum number of confirmations. 0 includes mempool entries.
        #[serde(default)]
        min_confirmations: u32,
    },
    /// List the active wallet's transaction history via the persistent GSP session.
    LightHistory {
        limit: u32,
        offset: u32,
    },
    /// List BIP-352 silent-payment detections accumulated in the persistent
    /// session's local scanner since auth.
    LightDetected,
    /// Read-only snapshot of the daemon's configured environment — the URLs
    /// it talks to, the network it's bound to, where it stores wallets.
    /// Useful for diagnostics + the GUI's settings panel.
    DaemonEnv,
    /// Phase 15: ask the daemon to fetch a release manifest from
    /// `manifest_url` (or the daemon-configured default if `None`),
    /// compare the manifest's version against the running daemon's
    /// version, and report whether an upgrade is available. The daemon
    /// only reports — it does not download or install anything.
    CheckForUpdate {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_url: Option<String>,
    },
    /// Stream future BIP-352 silent-payment detections from the persistent
    /// session as they arrive. The daemon keeps the connection open and emits
    /// `Response::PaymentDetected` envelopes (id=0) until the client closes
    /// the socket. The initial reply on the request's own id is an
    /// acknowledgement (`Response::Watching`).
    WatchPayments,
    /// List the active wallet's Ghost Locks via the persistent GSP session.
    LocksList,
    /// Ask GSP to prepare a new ghost lock for the active wallet.
    /// Server returns a funding address and required-sats; client funds it externally.
    LocksPrepare {
        capacity_sats: u64,
    },
    /// Confirm that a previously-prepared lock has been funded on-chain.
    LocksConfirm {
        lock_id: String,
        funding_txid: String,
    },
    /// Initiate a jump (key rotation) for an existing lock.
    /// Priority is one of: "normal" (default), "high", "urgent".
    LocksJump {
        lock_id: String,
        target_address: String,
        priority: String,
    },
    /// **Unilateral exit** — spend a Ghost Lock via the timelock
    /// recovery branch, with no operator cooperation. Daemon talks
    /// directly to the user-configured bitcoind, builds + signs +
    /// broadcasts the spend tx using the wallet's own
    /// recovery_secret. Works even if ghost-pay and ghost-gsp are
    /// permanently down. The maturation precondition (current
    /// height >= creation_height + recovery_blocks) is enforced
    /// before signing — bitcoin would reject the spend anyway, but
    /// surfacing it here gives a friendly error instead of a
    /// cryptic mempool rejection.
    LocksRecover {
        lock_id: String,
        /// Wallet-controlled L1 destination for the recovered funds.
        destination_address: String,
        /// Mining fee in sats. Subtracted from the lock's value.
        /// Caller responsible for picking a sane number; daemon
        /// refuses fee >= prev_value_sats.
        fee_sats: u64,
    },
    /// Prepare + sign + submit an L2 payment.
    /// Mode is `ghostpay` (the instant L2 ledger transfer); it is the
    /// only accepted value and the default. The legacy `wraith` and
    /// `confidential` values are rejected — unlinkable L1 spends go
    /// through the Mix flow, not Send.
    ///
    /// `shroud_max_ms` overrides the daemon's default outbound-broadcast
    /// shroud window for *this one* payment.
    ///
    /// * `None` (default) — use the daemon-wide setting from `WRAITHD_SHROUD_MAX_MS`.
    /// * `Some(0)` — bypass shroud, broadcast immediately. Use only when
    ///   latency matters more than origin privacy.
    /// * `Some(n)` — pick a uniform random delay in `[0, n]` ms.
    LightSend {
        recipient: String,
        amount_sats: u64,
        mode: String,
        memo: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shroud_max_ms: Option<u64>,
    },
    /// Create a new named wallet on disk and add it to the daemon's unlocked set.
    WalletCreate {
        name: String,
        passphrase: String,
    },
    /// Restore a wallet from an existing BIP-39 mnemonic. Equivalent to
    /// `WalletCreate` but with the seed supplied by the caller. The new
    /// keystore is encrypted under `passphrase` and added to the unlocked
    /// set; on success the daemon also makes it active.
    WalletImport {
        name: String,
        mnemonic: String,
        passphrase: String,
    },
    /// Unlock a named wallet by reading from disk + decrypting. Becomes active.
    WalletUnlock {
        name: String,
        passphrase: String,
    },
    /// Drop a named wallet from the unlocked set (or the active one if name is None).
    WalletLock {
        name: Option<String>,
    },
    /// List all on-disk wallets with unlocked / active status.
    WalletList,
    /// Set the active wallet (must already be unlocked).
    WalletSelect {
        name: String,
    },
    /// Status of the active wallet (or "no active wallet" if none).
    WalletStatus,
    /// Derive a key at a BIP32 path from the active wallet's keystore.
    WalletDerive {
        path: String,
    },
    /// Show the GSP auth identity (wallet_id + x-only auth pubkey) of the active wallet.
    WalletAuthInfo,
    /// Show the active wallet's BIP-352 Ghost ID (silent payment receive identity).
    WalletGhostId,
    /// Fetch the registered Ghost Glyph for `ghost_id` from ghost-pay.
    WalletGlyph {
        ghost_id: String,
    },
    /// Claim a designed Ghost Glyph for `ghost_id`. `pixels` is a
    /// 256-byte palette-index bitmap (values 0..25). Authenticated
    /// against ghost-pay via the internal-auth shared secret.
    WalletGlyphClaim {
        ghost_id: String,
        pixels: Vec<u8>,
    },
    /// Check whether a glyph bitmap is unclaimed. The daemon computes
    /// the bitmap hash from `pixels` and queries ghost-pay's
    /// availability endpoint.
    WalletGlyphCheck {
        pixels: Vec<u8>,
    },
    /// Export the active wallet's extended public key at `path`,
    /// formatted for use as a BIP-380 descriptor key fragment.
    /// `mainnet=true` emits xpub, `mainnet=false` emits tpub.
    /// Used by cosigners assembling a multisig descriptor in
    /// Sparrow / Specter / Bitcoin Core. The wallet's private key
    /// stays on the daemon — only the public extended key leaves.
    WalletExportXpub {
        path: String,
        #[serde(default)]
        mainnet: bool,
    },
    /// Parse a multisig descriptor and return its structure +
    /// first `address_count` derived receive addresses. No
    /// persistence — pure inspection. Lets the GUI validate a
    /// pasted descriptor before saving.
    MultisigDescriptorInspect {
        descriptor: String,
        #[serde(default = "default_address_count")]
        address_count: u32,
    },
    /// Persist a multisig descriptor under `name` for the active
    /// wallet. Errors if `name` already exists. The wallet's
    /// fingerprint must be present in the descriptor — otherwise
    /// the daemon refuses (would be a watch-only role we don't
    /// model yet).
    MultisigDescriptorSave {
        name: String,
        descriptor: String,
    },
    /// List multisig descriptors saved for the active wallet.
    MultisigDescriptorList,
    /// Return derived receive addresses for a saved descriptor,
    /// `count` of them starting at `start_index`. `internal=true`
    /// returns change-chain addresses instead.
    MultisigDescriptorAddresses {
        name: String,
        #[serde(default)]
        start_index: u32,
        #[serde(default = "default_address_count")]
        count: u32,
        #[serde(default)]
        internal: bool,
    },
    /// Delete a saved multisig descriptor for the active wallet.
    /// Idempotent — succeeds with `removed=false` if absent.
    MultisigDescriptorDelete {
        name: String,
    },
    /// Re-display a wallet's BIP39 mnemonic. Always re-prompts the passphrase.
    WalletShowMnemonic {
        name: String,
        passphrase: String,
    },
    /// Copy the on-disk encrypted keystore for `name` to `to_path` (a regular file).
    /// The file is already encrypted with the wallet passphrase.
    WalletExport {
        name: String,
        to_path: String,
    },
    /// Read an encrypted keystore from `from_path` and install it as wallet `name`.
    /// Refuses if `name` already exists on disk.
    WalletRestore {
        name: String,
        from_path: String,
    },
    /// Derive a BIP86 taproot receive address at index `index` from the active wallet.
    LightReceive {
        index: u32,
    },
    /// Phase 5b: drive the wallet's side of a Wraith Lite v1 mix
    /// against `coordinator_url`, up through the `/round-tx` fetch.
    /// Returns a [`WraithMixPreparedResponse`] carrying the unsigned
    /// bitcoin transaction the caller must sign for its own input.
    /// The daemon stashes the in-flight `PreparedMix` keyed by
    /// session_id; subsequent [`Request::WraithMixSubmit`] consumes it.
    ///
    /// v1 limitation: the daemon takes bond escrow as a precondition
    /// — the caller is responsible for arranging a real bond against
    /// (ghost_id, session_id) via ghost-pay (or, in dev, via the
    /// coordinator's MockBondLedger) before this call reaches
    /// `/inputs`. Phase C wiring will move this into the daemon.
    WraithMixPrepare {
        coordinator_url: String,
        /// Optional SOCKS5 proxy URL for the /outputs anonymous
        /// submission only. e.g. `socks5h://127.0.0.1:9050` for
        /// system Tor. None routes /outputs over the same direct
        /// HTTP transport as the rest of the protocol — fine for
        /// local dev, leaks the participant's IP in production.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socks5_proxy: Option<String>,
        /// Optional fallback coordinator URLs. Used in order if
        /// `coordinator_url` is unreachable (connect refused, timeout,
        /// DNS-unresolvable). HTTP error responses do NOT trigger
        /// failover — those mean a coordinator answered. See
        /// DESIGN_LITE §7 (signer handover via Active/Standby pool).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        coordinator_peers: Vec<String>,
        tier_id: String,
        ghost_id: String,
        bond_id_placeholder: String,
        utxo_txid: String,
        utxo_vout: u32,
        utxo_value_sats: u64,
        utxo_scriptpubkey_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        change_address: Option<String>,
        mix_output_address: String,
    },
    /// Phase 5b companion to [`Request::WraithMixPrepare`]. Submits
    /// the supplied witness for the previously-prepared session and
    /// drives the round to completion. Daemon discards the stashed
    /// `PreparedMix` after a successful submit (or on broadcast
    /// failure).
    WraithMixSubmit {
        session_id: String,
        /// Hex-encoded `bitcoin::Witness` (consensus-encoded
        /// length-prefixed witness stack).
        witness_hex: String,
    },
    /// Phase 5b: run a complete Wraith Lite mix in one shot. Daemon
    /// drives prepare_mix, computes the BIP-341 taproot key-path
    /// witness internally using the active wallet's keystore, then
    /// runs submit_witness. Returns
    /// [`Response::WraithMixCompleted`] on success — same response
    /// shape as the two-step flow.
    ///
    /// The wallet must own the input UTXO at a BIP86 derivation
    /// index ≤ `bip86_scan_max`; if `bip86_scan_max` is `None` the
    /// daemon scans 0..1024 by default.
    /// Fetch the coordinator's `/api/v1/pool/discover` payload —
    /// network, supported tiers, fee/bond rates. Mirrors the
    /// `Request::WraithMix*` shape (including `coordinator_peers`)
    /// so the discovery call participates in the same failover.
    WraithCoordinatorDiscover {
        coordinator_url: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        coordinator_peers: Vec<String>,
    },
    /// Resolve an elected coordinator endpoint for a mix of `tier_id` from the
    /// node's decentralised-election view (fetched THROUGH ghost-pay, never the
    /// pool API directly — wallet hard rule). The wallet shards on (tier, epoch)
    /// so all wallets wanting the same denomination this epoch converge on one
    /// seat. Reply: [`Response::WraithCoordinatorResolved`]. Falls back to a
    /// manual coordinator URL when this yields no endpoint.
    WraithResolveCoordinator {
        tier_id: String,
    },
    WraithMixOneShot {
        coordinator_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socks5_proxy: Option<String>,
        /// Optional fallback coordinator URLs. Same semantics as
        /// `WraithMixPrepare::coordinator_peers`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        coordinator_peers: Vec<String>,
        tier_id: String,
        ghost_id: String,
        bond_id_placeholder: String,
        utxo_txid: String,
        utxo_vout: u32,
        utxo_value_sats: u64,
        utxo_scriptpubkey_hex: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        change_address: Option<String>,
        mix_output_address: String,
        /// Optional BIP86 derivation index. When `None`, daemon
        /// scans 0..bip86_scan_max for an address whose
        /// scriptPubKey matches `utxo_scriptpubkey_hex`. When
        /// `Some(idx)`, daemon uses index `idx` directly and
        /// fails fast if it doesn't match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bip86_index: Option<u32>,
        /// Bound on the BIP86 scan. Default 1024.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bip86_scan_max: Option<u32>,
    },
    /// Decode a PSBT and return a per-input / per-output summary.
    /// Pure function — does not touch any wallet state, so unlike
    /// `PsbtSign` it works without an active wallet. Accepts either
    /// base64 or hex; the daemon sniffs the encoding.
    PsbtInspect {
        psbt: String,
    },
    /// Sign every input of a PSBT that the active wallet's keystore
    /// can sign. Inputs the keystore doesn't own are left untouched
    /// — multi-cosigner flows just chain `PsbtSign` across each
    /// participant's daemon. Returns the updated PSBT (same encoding
    /// as the input — base64 in, base64 out).
    ///
    /// `bip86_scan_max` bounds the derivation search per input
    /// (default 1024 — same as the Wraith mix scan).
    PsbtSign {
        psbt: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bip86_scan_max: Option<u32>,
    },
    /// Build an unsigned PSBT spending the active wallet's L1 UTXOs
    /// to `recipient_address`. Daemon scans 0..`bip86_scan_max`
    /// receive addresses against ghost-pay's `scantxoutset`, then
    /// runs greedy coin selection to cover `amount_sats + fee`.
    /// Change goes back to the next-derived BIP86 receive index
    /// (`change_index` if specified; otherwise `bip86_scan_max + 1`
    /// — i.e. just past the gap-limit so it's a fresh address).
    /// Returns the unsigned PSBT (base64) ready to feed into
    /// `PsbtSign` or export to a hardware wallet.
    PsbtCreate {
        recipient_address: String,
        amount_sats: u64,
        /// Fee rate in sats/vB. Default 5.
        #[serde(default = "default_fee_rate")]
        fee_rate_sats_per_vb: u64,
        /// BIP86 index to use for change. None → next index past the scan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        change_index: Option<u32>,
        /// Highest BIP86 index to scan when looking for spendable
        /// UTXOs. Default 32 — matches `default_l1_scan_max_index`.
        #[serde(default = "default_l1_scan_max_index")]
        bip86_scan_max: u32,
        /// Coin-control: if non-empty, only these outpoints are
        /// considered for selection. Daemon errors if any outpoint
        /// isn't in the wallet's scanned UTXO set (catches
        /// stale GUI state). Empty / absent → fall back to greedy
        /// over all spendable UTXOs.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        selected_outpoints: Vec<OutpointRef>,
    },
    /// Broadcast a finalized PSBT (or finalized raw tx hex) via
    /// ghost-pay → bitcoind's `sendrawtransaction`. The daemon
    /// extracts the tx from the PSBT before forwarding, so the
    /// caller doesn't have to know how to finalize. If the input
    /// is already raw tx hex (no PSBT magic), it's broadcast as-is.
    PsbtBroadcast {
        psbt_or_tx_hex: String,
    },
    /// BIP-125 fee-bump on an existing PSBT. Reduces the wallet's
    /// change output to absorb the higher fee, returns a fresh
    /// unsigned PSBT (signatures stripped — the sighash changes
    /// when output values change). Caller signs + broadcasts the
    /// result via the normal `PsbtSign` + `PsbtBroadcast` flow.
    /// `new_fee_rate_sats_per_vb` must strictly exceed the
    /// original rate or the call is a no-op (and rejected).
    PsbtBumpFee {
        psbt: String,
        new_fee_rate_sats_per_vb: u64,
        /// Highest BIP86 index to scan when locating the wallet's
        /// change output. Default 32 — matches the create-side
        /// default.
        #[serde(default = "default_l1_scan_max_index")]
        bip86_scan_max: u32,
    },
}

/// Default fee rate (sats/vB) used by PsbtCreate when the caller
/// doesn't specify one. 5 is a generous regtest/signet default; on
/// mainnet the GUI prompts the user for a fee rate before
/// reaching this code path.
pub(crate) fn default_fee_rate() -> u64 {
    5
}

/// Default number of multisig receive addresses to derive for
/// inspection / display. 10 fits a typical "show me a few" panel
/// without making the daemon do excessive secp work per call.
pub(crate) fn default_address_count() -> u32 {
    10
}

/// Wire shape for a coin-control outpoint reference. Stays a thin
/// `{txid, vout}` so it round-trips through every PSBT toolchain
/// without translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutpointRef {
    pub txid: String,
    pub vout: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Health(HealthResponse),
    Doctor(DoctorResponse),
    ChainStatus(ChainStatusResponse),
    GspPing(GspPingResponse),
    GspAuth(GspAuthResponse),
    GspSessionStatus(GspSessionStatusResponse),
    GspScanKeyRegistered {
        wallet_id: String,
        scan_pubkey_hex: String,
    },
    LightBalance(LightBalanceResponse),
    LightUtxos(LightUtxosResponse),
    LightL1Utxos(LightL1UtxosResponse),
    LightHistory(LightHistoryResponse),
    LightDetected(LightDetectedResponse),
    DaemonEnv(DaemonEnvResponse),
    CheckForUpdate(CheckForUpdateResponse),
    /// Acknowledgement of a `Request::WatchPayments`. Subsequent
    /// `PaymentDetected` envelopes (id=0) on the same connection are pushes,
    /// not replies.
    Watching,
    /// Unsolicited push: a new BIP-352 detection. Daemon sends with `id=0`.
    PaymentDetected(DetectedPaymentEntry),
    LocksList(LocksListResponse),
    LocksPrepared(LocksPreparedResponse),
    LocksConfirmed(LocksConfirmedResponse),
    LocksJumped(LocksJumpedResponse),
    /// Successful response to [`Request::LocksRecover`]. The
    /// recovery tx has been built, signed, and accepted by bitcoind.
    LocksRecovered(LocksRecoveredResponse),
    LightSent(LightSentResponse),
    WalletCreate(WalletCreateResponse),
    /// Reply to `Request::WalletImport`. We don't echo the mnemonic back —
    /// the caller already has it.
    WalletImported {
        name: String,
        path: String,
    },
    WalletUnlocked,
    WalletLocked {
        name: String,
    },
    WalletList(WalletListResponse),
    WalletSelected {
        name: String,
    },
    WalletStatus(WalletStatusResponse),
    WalletDerive(WalletDeriveResponse),
    WalletAuthInfo(WalletAuthInfoResponse),
    WalletGhostId(WalletGhostIdResponse),
    WalletGlyph(GlyphInfo),
    WalletGlyphClaimed(GlyphClaimResult),
    WalletGlyphChecked {
        available: bool,
    },
    WalletXpub(WalletXpubResponse),
    MultisigDescriptorInspected(MultisigDescriptorInspected),
    MultisigDescriptorSaved(MultisigDescriptorSaved),
    MultisigDescriptorList(MultisigDescriptorListResponse),
    MultisigDescriptorAddresses(MultisigDescriptorAddressesResponse),
    MultisigDescriptorDeleted {
        removed: bool,
    },
    WalletShowMnemonic(WalletShowMnemonicResponse),
    WalletExported {
        name: String,
        path: String,
        bytes: u64,
    },
    WalletRestored {
        name: String,
        path: String,
        bytes: u64,
    },
    LightReceive(LightReceiveResponse),
    /// Reply to [`Request::WraithMixPrepare`]. Carries the assembled
    /// unsigned bitcoin transaction + the metadata the caller needs
    /// to compute its own input witness.
    WraithCoordinatorDiscover(WraithDiscoverResponse),
    /// Reply to [`Request::WraithResolveCoordinator`]. `endpoint` is the elected
    /// coordinator to dial for the requested tier, or `None` when the election is
    /// off/pending/unadvertised (caller falls back to a manual URL). `epoch` is
    /// the election epoch the resolution was sharded on, when known.
    WraithCoordinatorResolved {
        endpoint: Option<String>,
        epoch: Option<u64>,
    },
    WraithMixPrepared(WraithMixPreparedResponse),
    /// Reply to [`Request::WraithMixSubmit`]. Carries the broadcast
    /// txid and the index of the wallet's mixed output.
    WraithMixCompleted(WraithMixCompletedResponse),
    PsbtInspected(PsbtInspectResponse),
    PsbtSigned(PsbtSignResponse),
    PsbtCreated(PsbtCreateResponse),
    PsbtBroadcast(PsbtBroadcastResponse),
    PsbtBumped(PsbtBumpFeeResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub daemon_version: String,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithDiscoverTier {
    pub id: String,
    pub denomination_sats: u64,
    pub min_participants: u32,
    pub max_participants: u32,
    pub bond_sats: u64,
    pub service_fee_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithDiscoverResponse {
    /// Coordinator URL that actually answered (may differ from the
    /// requested `coordinator_url` if the call rotated through
    /// `coordinator_peers`). UI shows this so users know which
    /// active they hit.
    pub answered_by: String,
    pub network: String,
    pub pool_id: String,
    pub service_fee_bps: u32,
    pub bond_bps: u32,
    pub fill_window_secs: u64,
    pub tiers: Vec<WraithDiscoverTier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithMixPreparedResponse {
    pub session_id: String,
    /// Hex-encoded unsigned `bitcoin::Transaction`. Caller signs the
    /// input at `input_index` (using `prev_amount_sats` for sighash)
    /// and submits the witness via [`Request::WraithMixSubmit`].
    pub unsigned_tx_hex: String,
    pub input_index: u32,
    pub prev_amount_sats: u64,
    pub mixed_output_tx_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithMixCompletedResponse {
    pub session_id: String,
    pub broadcast_txid: String,
    pub mixed_output_tx_index: u32,
}

/// Per-input row returned by `PsbtInspect`.
///
/// Field choices mirror Bitcoin Core's `decodepsbt` so existing
/// tooling stays a 1:1 mental map. Optional fields are `None` for
/// inputs the daemon couldn't fully decode (e.g. a witness UTXO
/// that's missing). Importantly, `is_signable_by_active_wallet` is
/// computed against the currently-loaded wallet's keystore: it
/// answers the user's question "will my Sign button do anything to
/// this input?" without making them parse derivation paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInputSummary {
    pub previous_txid: String,
    pub previous_vout: u32,
    /// Amount of the input we're consuming, if a witness UTXO or
    /// non-witness UTXO is attached. None when neither is set, which
    /// breaks signability (we'd be signing a sighash with no value
    /// commitment) — surface the row as un-signable.
    pub value_sats: Option<u64>,
    pub script_pubkey_hex: Option<String>,
    pub address: Option<String>,
    /// `true` if this input already carries a final scriptWitness
    /// or final scriptSig. Saves the GUI from re-rendering "ready
    /// to sign" pills on inputs that are already done.
    pub is_finalized: bool,
    /// Number of partial signatures attached. With multisig you
    /// expect this to grow toward the script's `k` threshold across
    /// rounds.
    pub partial_signatures: u32,
    /// True if the active wallet's keystore can produce a signature
    /// for this input. Computed by deriving up to
    /// `bip86_scan_max` BIP86 indices and checking the witness
    /// scriptPubKey against the result. Inactive when no wallet is
    /// loaded — surfaces the input as un-signable in that case.
    pub is_signable_by_active_wallet: bool,
}

/// Per-output row returned by `PsbtInspect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtOutputSummary {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub address: Option<String>,
    /// True if this output goes back to the active wallet (BIP86
    /// receive at any scanned index). Lets the GUI label change vs
    /// recipient outputs visually.
    pub is_owned_by_active_wallet: bool,
}

/// Reply to [`Request::PsbtInspect`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtInspectResponse {
    /// Network the daemon is running on. Inspector echos this so
    /// the GUI can warn loudly if the user tries to sign a mainnet
    /// PSBT in a regtest wallet (or vice versa).
    pub network: String,
    /// Hex of the unsigned tx contained in the PSBT.
    pub unsigned_tx_hex: String,
    /// txid of the unsigned tx — the malleability-free form, since
    /// signature data lives outside the txid pre-image for taproot.
    pub txid: String,
    pub inputs: Vec<PsbtInputSummary>,
    pub outputs: Vec<PsbtOutputSummary>,
    /// Total input value, when every input has a `value_sats`. None
    /// when at least one input is missing prevout info — the fee in
    /// that case is undeterminable from the PSBT alone.
    pub total_in_sats: Option<u64>,
    pub total_out_sats: u64,
    pub fee_sats: Option<u64>,
    /// True if every input is finalized — the PSBT is one
    /// `psbt_extract` away from a broadcast-ready transaction.
    pub is_complete: bool,
    /// Convenience flag — at least one input was signable but is
    /// not yet finalized, i.e. `PsbtSign` would do work.
    pub has_signable_inputs: bool,
}

/// Reply to [`Request::PsbtCreate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtCreateResponse {
    /// The unsigned PSBT, base64-encoded.
    pub psbt: String,
    /// Number of inputs the builder selected (greedy by descending
    /// value).
    pub input_count: u32,
    /// Sum of input values in sats.
    pub total_input_sats: u64,
    /// Recipient amount echoed back, for cross-check.
    pub recipient_sats: u64,
    /// Change going back to the wallet (0 means change was
    /// absorbed into the fee — residual was below dust).
    pub change_sats: u64,
    /// Mining fee in sats. Computed from `fee_rate_sats_per_vb` ×
    /// estimated vbytes; may exceed the requested rate × bytes
    /// when residual was rolled into the fee.
    pub fee_sats: u64,
    /// BIP86 derivation index used for change (None when no
    /// change output was needed).
    pub change_bip86_index: Option<u32>,
}

/// Reply to [`Request::PsbtBroadcast`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtBroadcastResponse {
    /// txid that bitcoind accepted.
    pub txid: String,
}

/// Reply to [`Request::PsbtBumpFee`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtBumpFeeResponse {
    /// The bumped PSBT, base64-encoded. Unsigned — caller resigns
    /// (sighash changed when output values changed) before
    /// broadcasting.
    pub psbt: String,
    pub old_fee_sats: u64,
    pub new_fee_sats: u64,
    pub old_change_sats: u64,
    pub new_change_sats: u64,
    pub input_count: u32,
}

/// Reply to [`Request::PsbtSign`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsbtSignResponse {
    /// PSBT after our signatures were added. Same encoding as the
    /// request input (base64 in → base64 out, hex in → hex out).
    pub psbt: String,
    /// Indices of inputs we successfully signed (zero-based against
    /// the unsigned tx's input list).
    pub signed_inputs: Vec<u32>,
    /// Total inputs in the PSBT — useful for the GUI to show
    /// "signed N of M" status.
    pub input_count: u32,
    /// Whether every input is now finalized (i.e. `psbt_extract`
    /// would succeed). Mirrors `PsbtInspectResponse::is_complete`
    /// after the sign step.
    pub is_complete: bool,
}

/// One row in the `Doctor` summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    /// `"pass"` / `"fail"` / `"skip"`.
    pub status: String,
    /// Human-readable detail line.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorResponse {
    pub checks: Vec<DoctorCheck>,
    pub all_pass: bool,
}

/// Status of the configured ghost-pay backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatusResponse {
    pub backend_version: String,
    pub network: String,
    pub has_keys: bool,
    pub lock_count: u64,
    pub active_sessions: u64,
    /// Latest verified-block height from the operator's bitcoind.
    #[serde(default)]
    pub chain_height: Option<u64>,
    /// Highest header bitcoind has seen. Equals chain_height when
    /// synced, exceeds it during IBD.
    #[serde(default)]
    pub chain_headers: Option<u64>,
    /// Bitcoin Core's verification progress (0..1). 1.0 ≈ synced.
    #[serde(default)]
    pub chain_verification_progress: Option<f64>,
    /// Bitcoin Core's IBD flag.
    #[serde(default)]
    pub chain_initial_block_download: Option<bool>,
    /// L2 chain tip — latest finalized ghost-pay block height.
    #[serde(default)]
    pub l2_height: Option<u64>,
    /// Current L2 epoch.
    #[serde(default)]
    pub l2_epoch: Option<u64>,
}

/// GSP WebSocket connectivity probe result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspPingResponse {
    pub server_time: i64,
    pub round_trip_ms: Option<i64>,
}

/// Result of `GspAuth` (register-if-needed + create-session).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspAuthResponse {
    pub wallet_id: String,
    /// Whether the register call returned "already registered".
    pub already_registered: bool,
    /// Truncated JWT (first 12 chars) for visibility — full token stays in the daemon.
    pub token_prefix: String,
    pub expires_at: i64,
}

/// Snapshot of the daemon's stored GSP session token + live connection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GspSessionStatusResponse {
    pub have_token: bool,
    /// Wallet name the token belongs to (the wallet that was active at `gsp_auth` time).
    pub wallet_name: Option<String>,
    pub wallet_id: Option<String>,
    pub expires_at: Option<i64>,
    pub remaining_secs: Option<i64>,
    /// One of: "disconnected", "connecting", "authenticating", "authenticated", "backoff".
    pub phase: Option<String>,
    /// Number of successful WS connects (1 = first connect, >1 = reconnects).
    pub connect_count: Option<u64>,
    pub last_error: Option<String>,
}

/// Active-wallet balance snapshot. `None` fields mean "no data yet"
/// (session not authenticated or first BalanceUpdate not received).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBalanceResponse {
    pub confirmed_sats: Option<u64>,
    pub unconfirmed_sats: Option<u64>,
    pub locked_sats: Option<u64>,
    pub received_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightUtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub confirmations: u32,
    pub script_type: String,
    pub spendable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightUtxosResponse {
    pub utxos: Vec<LightUtxoEntry>,
    pub total_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightL1UtxoEntry {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    /// Hex-encoded scriptPubKey of the output. Drop straight into
    /// the Wraith mix request's `utxo_scriptpubkey_hex`.
    pub scriptpubkey_hex: String,
    /// BIP86 derivation index that produced the address holding this
    /// UTXO. Drop into the mix request's `bip86_index` to skip the
    /// daemon's auto-scan.
    pub bip86_index: u32,
    pub address: String,
    pub confirmations: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightL1UtxosResponse {
    pub utxos: Vec<LightL1UtxoEntry>,
    pub total_sats: u64,
    /// Block height at which the underlying scantxoutset was taken,
    /// surfaced for diagnostic UI.
    pub chain_height: u32,
    /// The highest BIP86 index actually scanned. Echoes the request
    /// parameter back so the UI can show "scanned 0..N".
    pub scanned_max_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightHistoryEntry {
    pub txid: String,
    pub block_height: Option<u32>,
    pub timestamp: i64,
    /// Net satoshi change (positive = received, negative = sent).
    pub amount_sats: i64,
    pub fee_sats: Option<u64>,
    pub tx_type: String,
    pub confirmations: u32,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightHistoryResponse {
    pub transactions: Vec<LightHistoryEntry>,
    pub total_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPaymentEntry {
    pub txid: String,
    pub block_height: Option<u32>,
    pub vout: u32,
    pub amount_sats: Option<u64>,
    pub k: u32,
    pub received_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightDetectedResponse {
    pub detections: Vec<DetectedPaymentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEntry {
    pub lock_id: String,
    pub status: String,
    pub capacity_sats: u64,
    pub balance_sats: u64,
    pub denomination: String,
    pub timelock_tier: String,
    pub funding_address: String,
    pub funding_txid: Option<String>,
    pub funding_vout: Option<u32>,
    pub creation_height: u32,
    /// Absolute block height at which the lock's timelock matures and
    /// the wallet's unilateral recovery branch becomes spendable
    /// (`creation_height + recovery_blocks` per the lock's
    /// `timelock_tier`). Sourced from the operator-reported
    /// `recovery_height` on the GSP lock record.
    pub recovery_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksListResponse {
    pub locks: Vec<LockEntry>,
    pub total_locked_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksPreparedResponse {
    pub lock_id: String,
    pub funding_address: String,
    pub required_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksConfirmedResponse {
    pub lock_id: String,
    pub txid: String,
    pub block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksJumpedResponse {
    pub lock_id: String,
    /// Jump transaction id, if the server broadcast it.
    pub jump_txid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocksRecoveredResponse {
    pub lock_id: String,
    /// Txid bitcoind accepted into the mempool. Once it confirms,
    /// the lock's funds are back in the wallet's L1 control.
    pub broadcast_txid: String,
    /// Where the recovered funds went.
    pub destination_address: String,
    /// How much went to the destination (lock value minus fee).
    pub recovered_sats: u64,
    /// Mining fee paid.
    pub fee_sats: u64,
}

/// One binary entry in a release manifest. Mirrors the JSON shape produced
/// by `scripts/release-wraith.sh` so the daemon can parse manifests with
/// `serde_json::from_str` directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBinary {
    pub sha256: String,
    pub size: u64,
}

/// Wraith Wallet release manifest. Produced by `release-wraith.sh`,
/// optionally GPG-detached-signed alongside, consumed by the daemon's
/// CheckForUpdate handler and the `wraith verify` CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    pub triple: String,
    pub built: String,
    pub commit: String,
    pub rustc: String,
    pub tarball: String,
    pub tarball_sha256: String,
    pub binaries: std::collections::BTreeMap<String, ManifestBinary>,
}

/// Result of `Request::CheckForUpdate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckForUpdateResponse {
    /// Version reported by the running daemon (`CARGO_PKG_VERSION`).
    pub current_version: String,
    /// Version reported by the manifest, when fetch + parse succeeded.
    pub latest_version: Option<String>,
    /// `true` only when the fetched manifest's version is byte-equal to
    /// the running version. Different (newer or older) → `false`.
    pub up_to_date: bool,
    /// Where the manifest was fetched from (resolved from caller's
    /// `manifest_url` override, or the daemon-configured default).
    pub manifest_url: String,
    /// Tarball filename from the manifest, when present.
    pub tarball: Option<String>,
    /// Tarball sha256 from the manifest, when present.
    pub tarball_sha256: Option<String>,
}

/// Read-only daemon environment snapshot. Maps 1:1 to the WRAITHD_* env vars
/// that wraithd reads at startup, plus a couple of derived fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEnvResponse {
    /// Comma-separated list of ghost-pay URLs in failover order.
    pub ghost_pay_urls: Vec<String>,
    /// Comma-separated list of GSP WebSocket URLs in failover order.
    pub gsp_urls: Vec<String>,
    /// Network the daemon is bound to: `mainnet` / `signet` / `testnet` / `regtest`.
    pub network: String,
    /// Absolute path to the encrypted-keystore directory.
    pub wallets_dir: String,
    /// SOCKS5(h) proxy URL if Tor is enabled, otherwise `None`.
    pub tor_proxy: Option<String>,
    /// Absolute path to the IPC socket the daemon is listening on.
    pub socket_path: String,
    /// Idle-lock threshold in seconds; 0 means auto-lock is disabled.
    pub idle_lock_secs: u64,
    /// Phase 9 Shroud relay: max wallet-side outbound-broadcast delay in
    /// milliseconds. 0 means the wallet broadcasts immediately. The actual
    /// delay applied to each send is uniform random in `[0, this]`.
    pub shroud_max_ms: u64,
    /// Phase 15: URL of the release manifest the daemon's CheckForUpdate
    /// handler fetches by default. `None` when no auto-update channel is
    /// configured — the handler will still accept a per-call override.
    pub update_manifest_url: Option<String>,
    /// Kiosk mode active. When true, wallet-management ops
    /// (create/import/select/lock) are refused by the daemon. The
    /// GUI uses this to hide the wallet management UI and lock the
    /// app to the Merchant screen. Defaults false for older
    /// daemons — frontends should treat absence as "not in kiosk
    /// mode".
    #[serde(default)]
    pub kiosk_mode: bool,
}

/// Result of `LightSend` (PreparePayment + sign + SubmitSignedPayment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightSentResponse {
    pub payment_id: String,
    /// On-chain txid if the server broadcast the transaction. May be `None`
    /// for L2 payments that don't surface as a chain tx (e.g. ghostpay mode).
    pub txid: Option<String>,
    pub recipient: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub mode: String,
    /// Actual milliseconds the wallet held the signed payment before
    /// submitting to ghost-pay (Phase 9 Shroud relay). `None` when shroud
    /// was disabled (max=0) for this send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shroud_delay_ms: Option<u64>,
}

/// Returned after creating a fresh wallet — the mnemonic is shown once for backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCreateResponse {
    pub name: String,
    pub mnemonic: String,
    pub path: String,
}

/// Status of the active wallet, or `None` if no wallet is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletStatusResponse {
    pub active: Option<String>,
    pub path: Option<String>,
    pub unlocked: bool,
    /// Phase 13: signer info for the active wallet, when one is unlocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerInfoIpc>,
}

/// One entry in `WalletListResponse::wallets`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletListEntry {
    pub name: String,
    pub path: String,
    pub unlocked: bool,
    pub active: bool,
    /// Phase 13: which kind of signer backs this wallet, when unlocked.
    /// Hardware wallets surface here as `Some({kind: "ledger", …})`. None
    /// for locked wallets — we don't load the keystore just to peek at
    /// kind metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerInfoIpc>,
}

/// Wire-format mirror of `wraith-wallet-core::signer::SignerInfo`. Crosses the
/// IPC boundary so clients can render "Software" vs "Ledger Nano X" without
/// pulling the core crate in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerInfoIpc {
    /// `"software"` for the in-memory keystore; vendor identifier for
    /// hardware (e.g. `"ledger"`, `"coldcard"`).
    pub kind: String,
    /// Free-form human-readable label — model name, serial, etc.
    pub label: String,
    /// True when signing requires user approval on a separate device.
    /// The GUI uses this to decide whether to show a "confirm on device"
    /// banner during sends.
    pub interactive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletListResponse {
    pub wallets: Vec<WalletListEntry>,
}

/// Public key derived at a BIP32 path. Private material stays in the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletDeriveResponse {
    pub path: String,
    /// SEC1 compressed (33-byte) public key, hex-encoded.
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightReceiveResponse {
    pub address: String,
    pub index: u32,
    pub network: String,
    pub derivation_path: String,
}

/// GSP authentication identity for the unlocked wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAuthInfoResponse {
    /// `SHA256(auth_pubkey)[0..16]` hex.
    pub wallet_id: String,
    /// X-only auth public key (32 bytes), hex.
    pub auth_public_key_hex: String,
    /// BIP32 path the auth keypair is derived at.
    pub derivation_path: String,
}

/// The wallet's BIP-352 Ghost ID — share this string to receive payments.
/// Derived deterministically from the seed; same seed across wallet
/// implementations yields the same Ghost ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletGhostIdResponse {
    pub ghost_id: String,
    pub network: String,
    /// Compressed (33-byte) scan public key, hex. Public — given to a GSP
    /// to scan for incoming payments.
    pub scan_public_key_hex: String,
    /// Compressed (33-byte) spend public key, hex.
    pub spend_public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletShowMnemonicResponse {
    pub mnemonic: String,
}

/// The wallet's registered Ghost Glyph — a 16x16, 26-colour bitmap
/// bound to its Ghost ID. Mirrors ghost-pay's `GlyphInfoResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphInfo {
    pub ghost_id: String,
    /// 256 palette indices (0..25), row-major.
    pub pixels: Vec<u8>,
    /// SHA256("GhostGlyphBitmap/v1" || pixels), hex — uniqueness key.
    pub bitmap_hash: String,
    /// SHA256("GhostGlyph/v1" || pixels || ghost_id), hex — binding.
    pub commitment: String,
    /// Wraith deposit txid that funded the lock (None while pending).
    pub funding_txid: Option<String>,
    /// Unix timestamp the lock was funded (None while pending).
    pub registered_at: Option<u64>,
    /// One of: "none" / "pending" / "registered".
    pub status: String,
}

/// Result of claiming a Ghost Glyph. Mirrors ghost-pay's
/// `GlyphClaimResponse`. The glyph stays `pending` until its lock funds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphClaimResult {
    pub commitment: String,
    pub bitmap_hash: String,
    pub status: String,
}

/// One cosigner row inside a parsed descriptor — what
/// `MultisigDescriptorInspect` surfaces per key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigCosignerSummary {
    pub fingerprint_hex: String,
    pub origin_path: String,
    pub xpub: String,
    /// True when this cosigner is the active wallet (fingerprint
    /// match). The GUI uses this to highlight "this is you" in the
    /// cosigner list.
    pub is_us: bool,
}

/// Reply to [`Request::MultisigDescriptorInspect`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptorInspected {
    /// `"wsh-sortedmulti"` for v1. Future variants get distinct
    /// strings — `"tr-multi-a"`, etc. — without breaking older
    /// clients that match on this field.
    pub kind: String,
    pub k: u32,
    pub n: u32,
    pub cosigners: Vec<MultisigCosignerSummary>,
    /// True if any cosigner row's `is_us` is true. Without this,
    /// the descriptor can't be saved (we don't model watch-only
    /// roles yet).
    pub contains_us: bool,
    /// First N receive addresses (external chain). Length is
    /// capped by the request's `address_count`.
    pub addresses: Vec<String>,
    /// BIP-380 checksum stripped from the input, if any.
    pub checksum: Option<String>,
}

/// Reply to [`Request::MultisigDescriptorSave`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptorSaved {
    pub name: String,
    pub path: String,
}

/// One entry in [`Request::MultisigDescriptorList`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptorListEntry {
    pub name: String,
    pub kind: String,
    pub k: u32,
    pub n: u32,
    /// Master fingerprints of all cosigners, for at-a-glance
    /// identification.
    pub cosigner_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptorListResponse {
    pub descriptors: Vec<MultisigDescriptorListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptorAddressEntry {
    pub index: u32,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigDescriptorAddressesResponse {
    pub name: String,
    pub internal: bool,
    pub addresses: Vec<MultisigDescriptorAddressEntry>,
}

/// Reply to [`Request::WalletExportXpub`].
///
/// Public-only data — no private material. Field shape mirrors what
/// every multisig coordinator UI asks for when adding a cosigner:
/// the xpub (paste it into a key slot), the master fingerprint
/// (cross-check against the cosigner's hardware-wallet display),
/// the path (so the descriptor can be re-derived deterministically),
/// and a pre-assembled `[fp/path]xpub.../<0;1>/*` fragment that
/// drops directly into a `wsh(sortedmulti(...))` or
/// `tr(multi_a(...))` wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletXpubResponse {
    pub xpub: String,
    pub master_fingerprint_hex: String,
    pub path: String,
    pub descriptor_key_fragment: String,
    /// `"mainnet"` (xpub) or `"testnet"` (tpub) so the GUI can
    /// surface a network warning when the user picked a path that
    /// doesn't match the daemon's network.
    pub network_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(flatten)]
    pub payload: T,
}

impl<T> Envelope<T> {
    pub fn new(id: u64, payload: T) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let s = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&s).expect("deserialize")
    }

    #[test]
    fn envelope_request_round_trip() {
        // Sample a representative selection across each subsystem so we catch
        // schema drift early. The full Request variant set is exercised by the
        // CLI and GUI integration tests.
        let cases = vec![
            Request::Health,
            Request::Doctor,
            Request::WalletList,
            Request::WalletStatus,
            Request::WalletUnlock {
                name: "test".into(),
                passphrase: "p".repeat(32),
            },
            Request::WalletImport {
                name: "restored".into(),
                mnemonic: "abandon ".repeat(11) + "about",
                passphrase: "long-enough-passphrase".into(),
            },
            Request::WalletLock { name: None },
            Request::WalletSelect {
                name: "test".into(),
            },
            Request::LightBalance,
            Request::LightUtxos {
                min_confirmations: 1,
            },
            Request::LightHistory {
                limit: 50,
                offset: 0,
            },
            Request::LightReceive { index: 0 },
            Request::LightSend {
                recipient: "bc1qxyz".into(),
                amount_sats: 100_000,
                shroud_max_ms: None,
                mode: "onchain".into(),
                memo: Some("test".into()),
            },
            Request::LocksList,
            Request::LocksPrepare {
                capacity_sats: 1_000_000,
            },
            Request::DaemonEnv,
            Request::CheckForUpdate { manifest_url: None },
            Request::CheckForUpdate {
                manifest_url: Some("https://example.invalid/manifest.json".into()),
            },
        ];

        for req in cases {
            let env = Envelope::new(7, req.clone());
            let back: Envelope<Request> = roundtrip(&env);
            assert_eq!(back.id, 7);
            assert_eq!(back.jsonrpc, JSONRPC_VERSION);
            // Compare via JSON shape since Request doesn't impl PartialEq.
            assert_eq!(
                serde_json::to_value(&req).unwrap(),
                serde_json::to_value(&back.payload).unwrap()
            );
        }
    }

    #[test]
    fn malformed_envelopes_fail_cleanly() {
        // The dispatch loop relies on these being errors — never panics.
        let inputs = [
            "",
            "{",
            "null",
            "[]",
            "\"hello\"",
            "{\"jsonrpc\":\"2.0\"}",          // missing method/id
            "{\"jsonrpc\":\"2.0\",\"id\":1}", // missing method
            "{\"jsonrpc\":\"2.0\",\"id\":-1,\"method\":\"health\"}", // negative id
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"unknown_method_x\"}",
        ];
        for raw in inputs {
            let result: Result<Envelope<Request>, _> = serde_json::from_str(raw);
            assert!(result.is_err(), "expected error for input: {raw:?}");
        }
    }

    #[test]
    fn envelope_response_round_trip() {
        let cases = vec![
            Response::Health(HealthResponse {
                daemon_version: "1.8.0".into(),
                uptime_secs: 42,
            }),
            Response::WalletLocked {
                name: "default".into(),
            },
            Response::WalletImported {
                name: "restored".into(),
                path: "/tmp/restored.json".into(),
            },
            Response::DaemonEnv(DaemonEnvResponse {
                ghost_pay_urls: vec!["http://127.0.0.1:8800".into()],
                gsp_urls: vec!["ws://127.0.0.1:8900/ws/v1".into()],
                network: "signet".into(),
                wallets_dir: "/home/test/.wraith/wallets".into(),
                tor_proxy: None,
                socket_path: "/tmp/wraithd.sock".into(),
                idle_lock_secs: 900,
                shroud_max_ms: 5000,
                update_manifest_url: None,
                kiosk_mode: false,
            }),
            Response::WalletList(WalletListResponse {
                wallets: vec![WalletListEntry {
                    name: "default".into(),
                    path: "/tmp/x".into(),
                    unlocked: false,
                    active: false,
                    signer: None,
                }],
            }),
        ];
        for resp in cases {
            let env = Envelope::new(99, resp.clone());
            let back: Envelope<Response> = roundtrip(&env);
            assert_eq!(back.id, 99);
            assert_eq!(
                serde_json::to_value(&env.payload).unwrap(),
                serde_json::to_value(&back.payload).unwrap()
            );
        }
    }

    proptest::proptest! {
        // Parsing the IPC envelope from arbitrary bytes must NEVER panic.
        // The dispatch loop catches malformed JSON and returns an Error
        // envelope, but only if the underlying parser doesn't blow up first.
        // 4096 cases is plenty to catch obvious panics; raise via the
        // PROPTEST_CASES env var for ad-hoc deeper sweeps.
        #![proptest_config(proptest::test_runner::Config {
            cases: 4096,
            .. proptest::test_runner::Config::default()
        })]

        #[test]
        fn arbitrary_bytes_never_panic_envelope_request(bytes in proptest::collection::vec(0u8..=255, 0..1024)) {
            let _ = serde_json::from_slice::<Envelope<Request>>(&bytes);
        }

        #[test]
        fn arbitrary_strings_never_panic_envelope_request(s in ".{0,1024}") {
            let _ = serde_json::from_str::<Envelope<Request>>(&s);
        }

        // Round-trip stability: anything we ourselves serialise must
        // deserialise back to an equal value (via JSON-shape comparison,
        // since Request doesn't impl PartialEq). This catches accidental
        // schema drift introduced by serde annotations.
        #[test]
        fn well_formed_envelopes_round_trip(id in 0u64..=u64::MAX) {
            let env = Envelope::new(id, Request::Health);
            let s = serde_json::to_string(&env).unwrap();
            let back: Envelope<Request> = serde_json::from_str(&s).unwrap();
            proptest::prop_assert_eq!(back.id, id);
            proptest::prop_assert_eq!(
                serde_json::to_value(&env.payload).unwrap(),
                serde_json::to_value(&back.payload).unwrap()
            );
        }
    }

    #[test]
    fn passphrase_field_serialises_and_does_not_leak_into_other_variants() {
        // Sanity: a freshly-serialised WalletUnlock contains the passphrase
        // (we don't redact at the wire layer — the trust model relies on the
        // 0600 socket permissions instead). Make sure unrelated request
        // variants never carry that field, so a typo in dispatch can't ship
        // credentials by accident.
        let r = Request::WalletUnlock {
            name: "alice".into(),
            passphrase: "hunter2".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("hunter2"));

        for clean in [Request::Health, Request::Doctor, Request::WalletList] {
            let s = serde_json::to_string(&clean).unwrap();
            assert!(!s.contains("passphrase"));
        }
    }
}
