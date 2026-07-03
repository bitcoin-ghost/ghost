//! Tauri shell for the Wraith Wallet GUI.
//!
//! Phase 14 first slice: scaffold + a single Tauri command (`gsp_health`)
//! that round-trips a `Request::Health` to a running `wraithd` over its
//! local IPC endpoint (a Unix-domain socket on unix, a named pipe on
//! Windows). Frontend is a static `index.html` (no bundler needed) — a
//! React/Tauri/Vite migration can layer on top once the protocol surface
//! is fleshed out.

use interprocess::local_socket::traits::tokio::Stream as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, WindowEvent,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use wraith_wallet_ipc::{Envelope, Request, Response};

/// Full-duplex IPC stream to the daemon (Unix-domain socket on unix,
/// named pipe on Windows) via the `interprocess` crate.
type IpcStream = interprocess::local_socket::tokio::Stream;

/// Connect to the running `wraithd` over its local IPC endpoint.
async fn connect_daemon() -> std::io::Result<IpcStream> {
    let name = wraith_wallet_ipc::endpoint_name()?;
    IpcStream::connect(name).await
}

/// Resolve the path to a bundled binary shipped next to this executable.
///
/// Tauri's `externalBin` sidecars are installed alongside the main GUI
/// binary with the target-triple suffix stripped (`wraithd.exe` on
/// Windows, `wraithd` elsewhere). In a `cargo tauri dev` / cargo build
/// tree the same layout holds: `wraithd` sits next to `wraith-gui` in
/// `target/<profile>/`. So resolving relative to `current_exe` covers
/// both the packaged install and the dev flow with one codepath.
fn sidecar_path(name: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    #[cfg(windows)]
    let file = dir.join(format!("{name}.exe"));
    #[cfg(not(windows))]
    let file = dir.join(name);
    Some(file)
}

/// Best-effort: make sure a `wraithd` is running so the GUI has a daemon
/// to talk to on a packaged install.
///
/// The daemon is the unit of life, not the GUI (see the wallet's design
/// notes), so we never kill it and we never spawn a second one on top of
/// a live daemon: if the IPC endpoint already answers we leave it alone —
/// it may have been started by the CLI or a previous GUI session. Only
/// when nothing is listening do we launch the bundled `wraithd` sidecar,
/// detached so it outlives this window.
///
/// Every failure path here is non-fatal: the frontend already renders a
/// "daemon offline" state and surfaces connection errors, and the user
/// can start `wraithd` by hand. We must never block or panic app startup
/// over daemon management.
async fn ensure_daemon() {
    // Fast path: a daemon is already listening — do not disturb it.
    if connect_daemon().await.is_ok() {
        return;
    }

    let daemon_bin = match sidecar_path("wraithd") {
        Some(p) if p.is_file() => p,
        _ => {
            tracing::warn!(
                "no running wraithd and no bundled wraithd sidecar found next to the GUI; \
                 start the daemon manually"
            );
            return;
        }
    };

    // Spawn detached with stdio → null so the daemon outlives the GUI and
    // doesn't keep a dev console alive. Environment is inherited so the
    // usual WRAITHD_* configuration flows through.
    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Detach from the GUI's process group / console so terminal signals
    // (Ctrl-C in `cargo tauri dev`) and GUI exit don't take the daemon
    // down with them. Unix: new process group. Windows: DETACHED_PROCESS.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(DETACHED_PROCESS);
    }

    match cmd.spawn() {
        Ok(_) => {
            // Poll the endpoint for up to ~3s so early frontend calls land
            // on a bound daemon instead of racing the spawn.
            for _ in 0..50 {
                tokio::time::sleep(std::time::Duration::from_millis(60)).await;
                if connect_daemon().await.is_ok() {
                    tracing::info!(bin = %daemon_bin.display(), "started bundled wraithd");
                    return;
                }
            }
            tracing::warn!(
                bin = %daemon_bin.display(),
                "spawned wraithd but it did not bind its IPC endpoint within 3s"
            );
        }
        Err(e) => {
            tracing::warn!(bin = %daemon_bin.display(), error = %e, "failed to spawn bundled wraithd");
        }
    }
}

/// Coordinates the long-lived watch task so we don't accidentally spawn a
/// second one if the frontend calls `start_watch()` twice. Frontends that need
/// per-window subscriptions should manage that themselves; this is a
/// daemon-wide singleton from the Rust side's perspective.
struct WatchState {
    running: AtomicBool,
}

impl WatchState {
    fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
        }
    }
}

/// Tauri command: ask the daemon for its health and return a JSON-serializable
/// summary. Used by the frontend to render a "daemon up" badge.
#[tauri::command]
async fn daemon_health() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::Health).await?;
    serde_json::to_value(&resp).map_err(|e| e.to_string())
}

/// Tauri command: round-trip the daemon's `Doctor` summary so the GUI can
/// render a colour-coded checks list on the home view.
#[tauri::command]
async fn daemon_doctor() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::Doctor).await?;
    serde_json::to_value(&resp).map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_list() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletList).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_status() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletStatus).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_unlock(name: String, passphrase: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletUnlock { name, passphrase }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_lock(name: Option<String>) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletLock { name }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_select(name: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletSelect { name }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_delete(name: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletDelete { name }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_create(name: String, passphrase: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletCreate { name, passphrase }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_import(
    name: String,
    mnemonic: String,
    passphrase: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletImport {
        name,
        mnemonic,
        passphrase,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_show_mnemonic(
    name: String,
    passphrase: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletShowMnemonic { name, passphrase }).await?;
    to_value(&resp)
}

/// Back up wallet `name`'s encrypted keystore by copying it to
/// `to_path` (a destination file the user chose). The daemon performs
/// the copy itself and refuses to overwrite an existing file. The
/// keystore stays encrypted end-to-end — no plaintext key material
/// crosses this boundary.
#[tauri::command]
async fn wallet_export(name: String, to_path: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletExport { name, to_path }).await?;
    to_value(&resp)
}

/// Restore a wallet from a previously-exported encrypted keystore at
/// `from_path`, installing it as wallet `name`. The daemon refuses if
/// a wallet of that name already exists on disk.
#[tauri::command]
async fn wallet_restore(name: String, from_path: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletRestore { name, from_path }).await?;
    to_value(&resp)
}

/// Ask the daemon to fetch a release manifest (from `manifest_url`, or
/// the daemon-configured default when `None`) and compare its version
/// against the running daemon. The daemon only reports — it never
/// downloads or installs anything.
#[tauri::command]
async fn check_for_update(manifest_url: Option<String>) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::CheckForUpdate { manifest_url }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_balance() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightBalance).await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_receive(index: u32) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightReceive { index }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_history(limit: u32, offset: u32) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightHistory { limit, offset }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn daemon_env() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::DaemonEnv).await?;
    to_value(&resp)
}

#[tauri::command]
async fn chain_status() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::ChainStatus).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_ghost_id() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletGhostId).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_glyph(ghost_id: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletGlyph { ghost_id }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_glyph_claim(
    ghost_id: String,
    pixels: Vec<u8>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletGlyphClaim { ghost_id, pixels }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_glyph_check(pixels: Vec<u8>) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletGlyphCheck { pixels }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn wallet_auth_info() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletAuthInfo).await?;
    to_value(&resp)
}

#[tauri::command]
async fn gsp_register_scan_key() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::GspRegisterScanKey).await?;
    to_value(&resp)
}

#[tauri::command]
async fn gsp_session_status() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::GspSessionStatus).await?;
    to_value(&resp)
}

#[tauri::command]
async fn gsp_auth() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::GspAuth).await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_list() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksList).await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_prepare(capacity_sats: u64) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksPrepare { capacity_sats }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_confirm(lock_id: String, funding_txid: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksConfirm {
        lock_id,
        funding_txid,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn locks_jump(
    lock_id: String,
    target_address: String,
    priority: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksJump {
        lock_id,
        target_address,
        priority,
    })
    .await?;
    to_value(&resp)
}

/// Unilateral exit. Builds + signs + broadcasts a recovery spend
/// using the wallet's own recovery secret, after confirming the
/// timelock has matured. Talks straight to the configured ghostd —
/// no GSP, no operator cooperation.
#[tauri::command]
async fn locks_recover(
    lock_id: String,
    destination_address: String,
    fee_sats: u64,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LocksRecover {
        lock_id,
        destination_address,
        fee_sats,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_send(
    recipient: String,
    amount_sats: u64,
    mode: String,
    memo: Option<String>,
    shroud_max_ms: Option<u64>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightSend {
        recipient,
        amount_sats,
        mode,
        memo,
        shroud_max_ms,
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn light_utxos(min_confirmations: Option<u32>) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightUtxos {
        min_confirmations: min_confirmations.unwrap_or(0),
    })
    .await?;
    to_value(&resp)
}

/// Scan ghost-pay's bitcoind for unspent L1 outputs at the active
/// wallet's BIP86 receive addresses 0..`scan_max_index`. Each row
/// comes back tagged with the BIP86 index that derived its address,
/// ready to feed straight into a Wraith mix request.
#[tauri::command]
async fn light_l1_utxos(
    scan_max_index: Option<u32>,
    min_confirmations: Option<u32>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::LightL1Utxos {
        scan_max_index: scan_max_index.unwrap_or(32),
        min_confirmations: min_confirmations.unwrap_or(0),
    })
    .await?;
    to_value(&resp)
}

/// Fetch the coordinator's `/api/v1/pool/discover` payload —
/// network, supported tiers, fee + bond rates. Same
/// connect-error-rotation invariant as the mix calls: HTTP errors
/// propagate, only connection-level failures rotate to a peer.
#[tauri::command]
async fn wraith_coordinator_discover(
    coordinator_url: String,
    coordinator_peers: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WraithCoordinatorDiscover {
        coordinator_url,
        coordinator_peers: coordinator_peers.unwrap_or_default(),
    })
    .await?;
    to_value(&resp)
}

/// Resolve an elected coordinator endpoint for a given mixing tier from the
/// node's decentralised election (fetched through ghost-pay). Returns
/// `{ endpoint, epoch }`; `endpoint` is null when the election is off/pending,
/// in which case the UI keeps the manually-entered coordinator URL.
#[tauri::command]
async fn wraith_resolve_coordinator(tier_id: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WraithResolveCoordinator { tier_id }).await?;
    to_value(&resp)
}

/// One-shot Wraith Lite mix. Daemon enrols, signs the BIP-341
/// taproot key-path witness using the active wallet's BIP86
/// keystore, and drives the round to broadcast.
#[tauri::command]
async fn wraith_mix_run(
    coordinator_url: String,
    coordinator_peers: Vec<String>,
    socks5_proxy: Option<String>,
    tier_id: String,
    ghost_id: String,
    bond_id_placeholder: Option<String>,
    utxo_txid: String,
    utxo_vout: u32,
    utxo_value_sats: u64,
    utxo_scriptpubkey_hex: String,
    change_address: Option<String>,
    mix_output_address: String,
    bip86_index: Option<u32>,
    bip86_scan_max: Option<u32>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WraithMixOneShot {
        coordinator_url,
        coordinator_peers,
        socks5_proxy,
        tier_id,
        ghost_id,
        bond_id_placeholder: bond_id_placeholder.unwrap_or_else(|| "placeholder".to_string()),
        utxo_txid,
        utxo_vout,
        utxo_value_sats,
        utxo_scriptpubkey_hex,
        change_address,
        mix_output_address,
        bip86_index,
        bip86_scan_max,
    })
    .await?;
    to_value(&resp)
}

fn to_value(resp: &Response) -> Result<serde_json::Value, String> {
    serde_json::to_value(resp).map_err(|e| e.to_string())
}

/// Decode a PSBT (base64 or hex auto-detected) and return a
/// per-input/per-output summary. The flag
/// `is_signable_by_active_wallet` is filled in against the
/// currently-loaded wallet, so the GUI can render "you can sign
/// these N inputs" without touching keystore plumbing in TS.
#[tauri::command]
async fn psbt_inspect(psbt: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::PsbtInspect { psbt }).await?;
    to_value(&resp)
}

/// Sign every input the active wallet can sign. Returns the
/// updated PSBT in the same encoding as the input (base64 → base64,
/// hex → hex), plus the indices that were actually touched.
#[tauri::command]
async fn psbt_sign(psbt: String, bip86_scan_max: Option<u32>) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::PsbtSign {
        psbt,
        bip86_scan_max,
    })
    .await?;
    to_value(&resp)
}

/// Build an unsigned PSBT spending the active wallet's L1 UTXOs to
/// `recipient_address`. Daemon-side scan + selection — the GUI
/// doesn't see UTXOs directly unless it passes `selected_outpoints`
/// (coin control). Returns the unsigned PSBT (base64) plus a
/// fee/change breakdown.
#[tauri::command]
async fn psbt_create(
    recipient_address: String,
    amount_sats: u64,
    fee_rate_sats_per_vb: Option<u64>,
    change_index: Option<u32>,
    bip86_scan_max: Option<u32>,
    selected_outpoints: Option<Vec<wraith_wallet_ipc::OutpointRef>>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::PsbtCreate {
        recipient_address,
        amount_sats,
        fee_rate_sats_per_vb: fee_rate_sats_per_vb.unwrap_or(5),
        change_index,
        bip86_scan_max: bip86_scan_max.unwrap_or(32),
        selected_outpoints: selected_outpoints.unwrap_or_default(),
    })
    .await?;
    to_value(&resp)
}

/// Extract a fully-signed PSBT (or accept raw tx hex directly) and
/// broadcast it via ghost-pay → bitcoind. Returns the txid.
#[tauri::command]
async fn psbt_broadcast(psbt_or_tx_hex: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::PsbtBroadcast { psbt_or_tx_hex }).await?;
    to_value(&resp)
}

/// BIP-125 fee-bump on an existing PSBT. Returns a new unsigned
/// PSBT (sigs stripped because output values changed) ready to feed
/// back into psbt_sign + psbt_broadcast.
#[tauri::command]
async fn psbt_bump_fee(
    psbt: String,
    new_fee_rate_sats_per_vb: u64,
    bip86_scan_max: Option<u32>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::PsbtBumpFee {
        psbt,
        new_fee_rate_sats_per_vb,
        bip86_scan_max: bip86_scan_max.unwrap_or(32),
    })
    .await?;
    to_value(&resp)
}

/// Export the active wallet's xpub at `path`, formatted for use in
/// a multisig descriptor (wsh, tr, etc.) by an external coordinator.
/// Public-only — no private material crosses this boundary.
#[tauri::command]
async fn wallet_export_xpub(path: String, mainnet: bool) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::WalletExportXpub { path, mainnet }).await?;
    to_value(&resp)
}

/// Inspect a multisig descriptor — parse + derive first N addresses.
/// No persistence.
#[tauri::command]
async fn multisig_descriptor_inspect(
    descriptor: String,
    address_count: Option<u32>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::MultisigDescriptorInspect {
        descriptor,
        address_count: address_count.unwrap_or(10),
    })
    .await?;
    to_value(&resp)
}

/// Save a multisig descriptor under `name` for the active wallet.
#[tauri::command]
async fn multisig_descriptor_save(
    name: String,
    descriptor: String,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::MultisigDescriptorSave { name, descriptor }).await?;
    to_value(&resp)
}

#[tauri::command]
async fn multisig_descriptor_list() -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::MultisigDescriptorList).await?;
    to_value(&resp)
}

#[tauri::command]
async fn multisig_descriptor_addresses(
    name: String,
    start_index: Option<u32>,
    count: Option<u32>,
    internal: Option<bool>,
) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::MultisigDescriptorAddresses {
        name,
        start_index: start_index.unwrap_or(0),
        count: count.unwrap_or(10),
        internal: internal.unwrap_or(false),
    })
    .await?;
    to_value(&resp)
}

#[tauri::command]
async fn multisig_descriptor_delete(name: String) -> Result<serde_json::Value, String> {
    let resp = call_daemon(Request::MultisigDescriptorDelete { name }).await?;
    to_value(&resp)
}

/// Start the daemon watch subscription if it isn't already running.
/// Forwards each `PaymentDetected` push to the frontend as a Tauri event
/// named `wraith://payment-detected`. Idempotent — safe to call from
/// multiple windows.
#[tauri::command]
async fn start_watch(
    app: AppHandle,
    state: tauri::State<'_, Arc<WatchState>>,
) -> Result<(), String> {
    if state
        .running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok(()); // already running
    }
    let app = app.clone();
    let state = state.inner().clone();
    tokio::spawn(async move {
        if let Err(e) = run_watch_loop(&app).await {
            // Surface the failure to the frontend so it can show a banner.
            let _ = app.emit("wraith://watch-error", serde_json::json!({ "message": e }));
        }
        state.running.store(false, Ordering::SeqCst);
    });
    Ok(())
}

async fn run_watch_loop(app: &AppHandle) -> Result<(), String> {
    let stream = connect_daemon()
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let (reader, mut writer) = stream.split();
    let mut line = serde_json::to_string(&Envelope::new(1, Request::WatchPayments))
        .map_err(|e| format!("serialise: {e}"))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut reader = BufReader::new(reader);
    loop {
        let mut buf = String::new();
        match reader.read_line(&mut buf).await {
            Ok(0) => return Ok(()), // daemon closed
            Ok(_) => {
                let env: Envelope<Response> = match serde_json::from_str(&buf) {
                    Ok(e) => e,
                    Err(_) => continue, // skip bad lines, keep stream alive
                };
                match env.payload {
                    Response::Watching => {}
                    Response::PaymentDetected(d) => {
                        let _ = app.emit(
                            "wraith://payment-detected",
                            serde_json::json!({
                                "txid": d.txid,
                                "block_height": d.block_height,
                                "vout": d.vout,
                                "amount_sats": d.amount_sats,
                                "k": d.k,
                                "received_at": d.received_at,
                            }),
                        );
                    }
                    Response::Error(e) => return Err(e.message),
                    _ => {}
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
}

/// Send a request to the running wraithd daemon over its local IPC endpoint.
/// Returns the parsed [`Response`] payload (without the JSON-RPC envelope).
async fn call_daemon(request: Request) -> Result<Response, String> {
    let stream = connect_daemon().await.map_err(|e| {
        format!(
            "could not connect to wraithd at {}: {e} (is the daemon running?)",
            wraith_wallet_ipc::endpoint_display()
        )
    })?;
    let (reader, mut writer) = stream.split();
    let mut line =
        serde_json::to_string(&Envelope::new(1, request)).map_err(|e| format!("serialise: {e}"))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    writer
        .shutdown()
        .await
        .map_err(|e| format!("shutdown: {e}"))?;
    let mut response_line = String::new();
    BufReader::new(reader)
        .read_line(&mut response_line)
        .await
        .map_err(|e| format!("read: {e}"))?;
    let envelope: Envelope<Response> =
        serde_json::from_str(&response_line).map_err(|e| format!("decode: {e}"))?;
    Ok(envelope.payload)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tauri::Builder::default()
        .manage(Arc::new(WatchState::new()))
        .setup(|app| {
            // Make sure a daemon is up. On a packaged install `wraithd` ships
            // as a Tauri sidecar next to this binary; spawn it if nothing is
            // already listening. Async + best-effort so startup never blocks
            // on it (the frontend tolerates the daemon being briefly absent).
            tauri::async_runtime::spawn(ensure_daemon());

            // Build a minimal tray menu — show / hide / quit. Daemon ("wraithd")
            // runs as a separate process, so quitting the GUI never stops the
            // wallet itself; the menu wording reflects that.
            let show = MenuItem::with_id(app, "show", "Show window", true, None::<&str>)?;
            let hide = MenuItem::with_id(app, "hide", "Hide window", true, None::<&str>)?;
            let quit_gui = MenuItem::with_id(
                app,
                "quit_gui",
                "Quit GUI (daemon keeps running)",
                true,
                None::<&str>,
            )?;
            let menu = Menu::with_items(app, &[&show, &hide, &quit_gui])?;

            let _tray = TrayIconBuilder::with_id("wraith-tray")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("Wraith Wallet")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.unminimize();
                            let _ = w.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.hide();
                        }
                    }
                    "quit_gui" => {
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Single-click on the tray icon toggles the main window —
                    // matches the muscle memory most desktop wallets train.
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            if w.is_visible().unwrap_or(false) {
                                let _ = w.hide();
                            } else {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it instead of exiting; the user has to
            // pick "Quit GUI" from the tray to actually terminate this process.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            daemon_health,
            daemon_doctor,
            daemon_env,
            chain_status,
            wallet_list,
            wallet_status,
            wallet_unlock,
            wallet_lock,
            wallet_select,
            wallet_delete,
            wallet_create,
            wallet_import,
            wallet_show_mnemonic,
            wallet_export,
            wallet_restore,
            check_for_update,
            light_balance,
            light_receive,
            light_history,
            light_send,
            light_utxos,
            light_l1_utxos,
            wraith_coordinator_discover,
            wraith_resolve_coordinator,
            wraith_mix_run,
            wallet_ghost_id,
            wallet_glyph,
            wallet_glyph_claim,
            wallet_glyph_check,
            wallet_auth_info,
            gsp_register_scan_key,
            gsp_session_status,
            gsp_auth,
            locks_list,
            locks_prepare,
            locks_confirm,
            locks_jump,
            locks_recover,
            psbt_inspect,
            psbt_sign,
            psbt_create,
            psbt_broadcast,
            psbt_bump_fee,
            wallet_export_xpub,
            multisig_descriptor_inspect,
            multisig_descriptor_save,
            multisig_descriptor_list,
            multisig_descriptor_addresses,
            multisig_descriptor_delete,
            start_watch,
        ])
        .run(tauri::generate_context!())
        .expect("error while running wraith-wallet-gui");
}
