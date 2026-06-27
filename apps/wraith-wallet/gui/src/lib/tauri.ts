// Typed wrappers around the Tauri commands defined in
// `src-tauri/src/lib.rs`. Every function here is a thin shim that
// forwards to `invoke()` and gives the frontend a typed return shape.
//
// The Rust side returns `serde_json::Value` for most commands; we
// narrow at this boundary using the response variants from
// `wraith_wallet_ipc::Response`. Shapes drift if the IPC enum
// changes, so when something here looks wrong the first place to
// look is `apps/wraith-wallet/ipc/src/lib.rs`.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

// ----- Response shape helpers --------------------------------------------

/**
 * Daemon Response is internally-tagged (`{ "result": "...", ...payload }`)
 * after serde's snake_case rename. Older variants (and the `Error` arm)
 * lift the payload under a separate top-level key. We accept both shapes
 * here.
 *
 * Crucially: if the daemon returned an `Error` response, throw with the
 * message instead of returning a malformed payload to the caller. Without
 * this, every screen that does `setX(resp.field)` blew up with
 * "undefined is not an object" — ate the actual diagnostic, took the
 * whole app to a blank screen.
 */
function unwrap<T = unknown>(resp: unknown): { variant: string; payload: T } {
  if (resp == null || typeof resp !== "object") {
    throw new Error(`unexpected response shape: ${JSON.stringify(resp)}`);
  }
  const obj = resp as Record<string, unknown>;
  // Internally-tagged form: { "result": "<variant>", ...payload-fields }.
  if (typeof obj.result === "string") {
    const variant = obj.result;
    if (variant === "error") {
      const msg =
        typeof obj.message === "string"
          ? obj.message
          : "daemon returned an error with no message";
      throw new Error(msg);
    }
    // Strip the discriminator and return the rest as the payload.
    const { result: _drop, ...payload } = obj;
    void _drop;
    return { variant, payload: payload as unknown as T };
  }
  // Externally-tagged fallback: { "Variant": { ...payload } }.
  const entries = Object.entries(obj);
  if (entries.length === 0) {
    return { variant: "(empty)", payload: undefined as T };
  }
  const [variant, payload] = entries[0];
  return { variant, payload: payload as T };
}

// ----- Daemon ------------------------------------------------------------

export interface HealthResponse {
  /// Daemon binary version (e.g. "1.8.0"). Wire field name is
  /// `daemon_version` — the wrapper renames so frontend code can
  /// say `health.version` matching common convention.
  version: string;
  uptime_secs: number;
  /// Synthesised by the wrapper from the response presence:
  /// `"ok"` if the call succeeded, otherwise the wrapper throws.
  /// Frontend was reading `health.status` to mean "did the daemon
  /// reply" — we keep that semantic.
  status: string;
}

interface WireHealthResponse {
  daemon_version: string;
  uptime_secs: number;
}

export async function daemonHealth(): Promise<HealthResponse> {
  const resp = await invoke("daemon_health");
  const raw = unwrap<WireHealthResponse>(resp).payload;
  return {
    version: raw.daemon_version,
    uptime_secs: raw.uptime_secs,
    status: "ok",
  };
}

export interface DoctorCheck {
  name: string;
  /// `"pass"` / `"fail"` / `"skip"`.
  status: string;
  detail: string;
}

export interface DoctorResponse {
  checks: DoctorCheck[];
  all_pass: boolean;
}

export async function daemonDoctor(): Promise<DoctorResponse> {
  const resp = await invoke("daemon_doctor");
  return unwrap<DoctorResponse>(resp).payload;
}

export interface DaemonEnvResponse {
  network: string;
  ghost_pay_urls: string[];
  gsp_urls: string[];
  socket_path: string;
  wallets_dir: string;
  /// Optional Tor SOCKS5 URL the daemon routes outbound REST through.
  tor_proxy: string | null;
  /// Idle auto-lock threshold in seconds. 0 means auto-lock is
  /// disabled. Set at boot via WRAITHD_IDLE_LOCK_SECS.
  idle_lock_secs: number;
  /// Phase 9 Shroud relay: max wallet-side outbound-broadcast delay
  /// in milliseconds. 0 disables. Each send picks a random delay
  /// in [0, this].
  shroud_max_ms: number;
  /// Kiosk mode flag. When true, the GUI hides the nav and locks
  /// the user to the Merchant screen — wallet management is
  /// disabled at the daemon. Frontends should treat absence as
  /// "not in kiosk mode" for compatibility with older daemons.
  kiosk_mode?: boolean;
}

export async function daemonEnv(): Promise<DaemonEnvResponse> {
  const resp = await invoke("daemon_env");
  return unwrap<DaemonEnvResponse>(resp).payload;
}

export interface ChainStatusResponse {
  backend_version: string;
  network: string;
  has_keys: boolean;
  lock_count: number;
  active_sessions: number;
  /// L1 verified block height. `null` if bitcoind was unreachable
  /// from ghost-pay at status time.
  chain_height: number | null;
  /// Highest L1 header seen. Equals `chain_height` when synced.
  chain_headers: number | null;
  /// Bitcoin Core verification progress (0..1).
  chain_verification_progress: number | null;
  /// Initial-block-download flag — true while still syncing.
  chain_initial_block_download: boolean | null;
  /// L2 chain tip — latest finalized ghost-pay block height.
  l2_height: number | null;
  /// Current L2 epoch (height / L2_EPOCH_BLOCKS).
  l2_epoch: number | null;
}

export async function chainStatus(): Promise<ChainStatusResponse> {
  const resp = await invoke("chain_status");
  return unwrap<ChainStatusResponse>(resp).payload;
}

// ----- Wallet ------------------------------------------------------------

export interface WalletEntry {
  name: string;
  ghost_id?: string;
  is_active: boolean;
  is_unlocked: boolean;
}

export interface WalletListResponse {
  wallets: WalletEntry[];
  /// Computed client-side from `wallets[].is_active` — the daemon's
  /// `WalletList` response doesn't surface this at the top level,
  /// only as a per-entry flag. Matching the older API shape so
  /// existing call sites keep working.
  active: string | null;
}

/// Wire-format entry from the daemon's WalletListResponse — matches
/// `wraith_wallet_ipc::WalletListEntry` exactly. Field names differ
/// from the frontend's `WalletEntry` (which uses `is_active` /
/// `is_unlocked`), so the wrapper adapts. Older versions of the
/// frontend assumed the wire shape was the same as `WalletEntry`,
/// which is why every call site silently received `undefined` for
/// the field accesses and `wallets.length` errored on the empty
/// state pre-fix.
interface WireWalletListEntry {
  name: string;
  path: string;
  active: boolean;
  unlocked: boolean;
}

interface WireWalletListResponse {
  wallets: WireWalletListEntry[];
}

export async function walletList(): Promise<WalletListResponse> {
  const resp = await invoke("wallet_list");
  const raw = unwrap<WireWalletListResponse>(resp).payload;
  const wallets: WalletEntry[] = (raw.wallets ?? []).map((w) => ({
    name: w.name,
    is_active: w.active,
    is_unlocked: w.unlocked,
    // ghost_id isn't in the daemon's WalletListEntry today; leave
    // unset so the screen renders an em-dash. A separate
    // walletGhostId() call still exposes it for the active wallet.
  }));
  const activeEntry = wallets.find((w) => w.is_active);
  return {
    wallets,
    active: activeEntry ? activeEntry.name : null,
  };
}

export interface WalletStatusResponse {
  active: string | null;
  unlocked: boolean;
  ghost_id?: string;
  network: string;
}

export async function walletStatus(): Promise<WalletStatusResponse> {
  const resp = await invoke("wallet_status");
  return unwrap<WalletStatusResponse>(resp).payload;
}

export interface WalletCreateResult {
  name: string;
  /// 12-word BIP39 mnemonic. Returned exactly once at create time.
  /// The caller MUST display this and prompt the user to write it
  /// down — without it, fund recovery is impossible. After the
  /// initial display, retrieving the mnemonic requires the
  /// passphrase via `walletShowMnemonic`.
  mnemonic: string;
  path: string;
}

export async function walletCreate(
  name: string,
  passphrase: string,
): Promise<WalletCreateResult> {
  const resp = await invoke("wallet_create", { name, passphrase });
  return unwrap<WalletCreateResult>(resp).payload;
}

export async function walletImport(
  name: string,
  mnemonic: string,
  passphrase: string,
): Promise<{ name: string; path: string }> {
  const resp = await invoke("wallet_import", { name, mnemonic, passphrase });
  return unwrap<{ name: string; path: string }>(resp).payload;
}

export async function walletShowMnemonic(
  name: string,
  passphrase: string,
): Promise<{ name: string; mnemonic: string }> {
  const resp = await invoke("wallet_show_mnemonic", { name, passphrase });
  return unwrap<{ name: string; mnemonic: string }>(resp).payload;
}

export async function walletUnlock(
  name: string,
  passphrase: string,
): Promise<unknown> {
  return await invoke("wallet_unlock", { name, passphrase });
}

export async function walletLock(name: string | null): Promise<unknown> {
  return await invoke("wallet_lock", { name });
}

export async function walletSelect(name: string): Promise<unknown> {
  return await invoke("wallet_select", { name });
}

export async function walletGhostId(): Promise<{
  ghost_id: string;
  network: string;
  scan_public_key_hex: string;
  spend_public_key_hex: string;
}> {
  const resp = await invoke("wallet_ghost_id");
  return unwrap<{
    ghost_id: string;
    network: string;
    scan_public_key_hex: string;
    spend_public_key_hex: string;
  }>(resp).payload;
}

// ----- Ghost Glyph -------------------------------------------------------

export interface GlyphInfo {
  ghost_id: string;
  /// 256 palette indices (0..25), row-major.
  pixels: number[];
  /// SHA256("GhostGlyphBitmap/v1" || pixels), hex — uniqueness key.
  bitmap_hash: string;
  /// SHA256("GhostGlyph/v1" || pixels || ghost_id), hex — binding.
  commitment: string;
  /// Wraith deposit txid that funded the lock (null while pending).
  funding_txid: string | null;
  /// Unix timestamp the lock was funded (null while pending).
  registered_at: number | null;
  /// One of: "none" / "pending" / "registered".
  status: string;
}

export interface GlyphClaimResult {
  commitment: string;
  bitmap_hash: string;
  status: string;
}

/// Fetch the registered Ghost Glyph for `ghostId`. Throws if the
/// daemon returns an error (e.g. ghost-pay 404 — no glyph yet); the
/// caller treats that as "not yet designed".
export async function getGlyph(ghostId: string): Promise<GlyphInfo> {
  const resp = await invoke("wallet_glyph", { ghostId });
  return unwrap<GlyphInfo>(resp).payload;
}

/// Claim a designed glyph. `pixels` is a 256-length array of palette
/// indices (0..25). Authenticated at the daemon via internal-auth.
export async function claimGlyph(
  ghostId: string,
  pixels: number[],
): Promise<GlyphClaimResult> {
  const resp = await invoke("wallet_glyph_claim", { ghostId, pixels });
  return unwrap<GlyphClaimResult>(resp).payload;
}

/// Check whether the bitmap formed by `pixels` is unclaimed. The
/// daemon computes the bitmap hash and queries ghost-pay.
export async function checkGlyph(
  pixels: number[],
): Promise<{ available: boolean }> {
  const resp = await invoke("wallet_glyph_check", { pixels });
  return unwrap<{ available: boolean }>(resp).payload;
}

// ----- Light wallet (L2) -------------------------------------------------

export interface LightBalanceResponse {
  /// On-chain confirmed balance, in sats. `null` when no
  /// BalanceUpdate has arrived yet (session not authenticated, or
  /// first update not received).
  confirmed_sats: number | null;
  unconfirmed_sats: number | null;
  /// Sats currently inside an active Ghost Lock and therefore
  /// unspendable until reconciled.
  locked_sats: number | null;
  /// Server time of the latest BalanceUpdate, unix epoch seconds.
  received_at: number | null;
}

export async function lightBalance(): Promise<LightBalanceResponse> {
  const resp = await invoke("light_balance");
  return unwrap<LightBalanceResponse>(resp).payload;
}

export interface LightHistoryEntry {
  txid: string;
  block_height: number | null;
  timestamp: number;
  amount_sats: number;
  fee_sats: number | null;
  tx_type: string;
  confirmations: number;
  memo: string | null;
}

export interface LightHistoryResponse {
  transactions: LightHistoryEntry[];
  total_count: number;
}

export async function lightHistory(
  limit = 50,
  offset = 0,
): Promise<LightHistoryResponse> {
  const resp = await invoke("light_history", { limit, offset });
  return unwrap<LightHistoryResponse>(resp).payload;
}

export interface LightReceiveResponse {
  address: string;
  index: number;
  network: string;
}

export async function lightReceive(index = 0): Promise<LightReceiveResponse> {
  const resp = await invoke("light_receive", { index });
  return unwrap<LightReceiveResponse>(resp).payload;
}

export type LightSendMode = "ghostpay" | "wraith" | "confidential";

export async function lightSend(
  recipient: string,
  amount_sats: number,
  mode: LightSendMode = "ghostpay",
  memo?: string,
  shroud_max_ms?: number,
): Promise<unknown> {
  return await invoke("light_send", {
    recipient,
    amountSats: amount_sats,
    mode,
    memo,
    shroudMaxMs: shroud_max_ms,
  });
}

export interface LightUtxoEntry {
  txid: string;
  vout: number;
  amount_sats: number;
  confirmations: number;
  script_type: string;
  spendable: boolean;
}

export interface LightUtxosResponse {
  utxos: LightUtxoEntry[];
  total_sats: number;
}

export async function lightUtxos(
  min_confirmations = 0,
): Promise<LightUtxosResponse> {
  const resp = await invoke("light_utxos", { minConfirmations: min_confirmations });
  return unwrap<LightUtxosResponse>(resp).payload;
}

export interface LightL1UtxoEntry {
  txid: string;
  vout: number;
  amount_sats: number;
  scriptpubkey_hex: string;
  /// BIP86 derivation index that produced the address holding this
  /// UTXO. Drop into a Wraith mix request's `bip86_index` to skip
  /// the daemon-side scan.
  bip86_index: number;
  address: string;
  confirmations: number;
  height: number;
}

export interface LightL1UtxosResponse {
  utxos: LightL1UtxoEntry[];
  total_sats: number;
  chain_height: number;
  scanned_max_index: number;
}

/// Scan ghost-pay's bitcoind for unspent L1 outputs at the active
/// wallet's BIP86 receive addresses 0..`scan_max_index`. Mainnet
/// scantxoutset takes 5-15s; signet/regtest sub-second. Surface
/// the latency in any UI.
export async function lightL1Utxos(
  scan_max_index = 32,
  min_confirmations = 0,
): Promise<LightL1UtxosResponse> {
  const resp = await invoke("light_l1_utxos", {
    scanMaxIndex: scan_max_index,
    minConfirmations: min_confirmations,
  });
  return unwrap<LightL1UtxosResponse>(resp).payload;
}

// ----- Wraith Lite (CoinJoin mix) ----------------------------------------

export interface WraithDiscoverTier {
  id: string;
  denomination_sats: number;
  min_participants: number;
  max_participants: number;
  bond_sats: number;
  service_fee_sats: number;
}

export interface WraithDiscoverResult {
  /// Coordinator URL that actually answered (may differ from the
  /// requested `coordinator_url` if the call rotated through
  /// `coordinator_peers`).
  answered_by: string;
  network: string;
  pool_id: string;
  service_fee_bps: number;
  bond_bps: number;
  fill_window_secs: number;
  tiers: WraithDiscoverTier[];
}

/// Fetch a coordinator's `/api/v1/pool/discover` payload. Same
/// failover semantics as the mix calls — connect errors rotate to
/// the next peer; HTTP errors propagate.
export async function wraithCoordinatorDiscover(
  coordinator_url: string,
  coordinator_peers?: string[],
): Promise<WraithDiscoverResult> {
  const resp = await invoke("wraith_coordinator_discover", {
    coordinatorUrl: coordinator_url,
    coordinatorPeers: coordinator_peers ?? [],
  });
  return unwrap<WraithDiscoverResult>(resp).payload;
}

export interface WraithMixCompleted {
  session_id: string;
  broadcast_txid: string;
  mixed_output_tx_index: number;
}

export interface WraithMixRunArgs {
  coordinator_url: string;
  coordinator_peers?: string[];
  socks5_proxy?: string;
  tier_id: string;
  ghost_id: string;
  bond_id_placeholder?: string;
  utxo_txid: string;
  utxo_vout: number;
  utxo_value_sats: number;
  utxo_scriptpubkey_hex: string;
  change_address?: string;
  mix_output_address: string;
  bip86_index?: number;
  bip86_scan_max?: number;
}

/// One-shot Wraith Lite CoinJoin. Daemon enrols, signs the
/// taproot key-path witness using the active wallet's BIP86
/// keystore, and drives the round to broadcast.
export async function wraithMixRun(
  args: WraithMixRunArgs,
): Promise<WraithMixCompleted> {
  const resp = await invoke("wraith_mix_run", {
    coordinatorUrl: args.coordinator_url,
    coordinatorPeers: args.coordinator_peers ?? [],
    socks5Proxy: args.socks5_proxy,
    tierId: args.tier_id,
    ghostId: args.ghost_id,
    bondIdPlaceholder: args.bond_id_placeholder,
    utxoTxid: args.utxo_txid,
    utxoVout: args.utxo_vout,
    utxoValueSats: args.utxo_value_sats,
    utxoScriptpubkeyHex: args.utxo_scriptpubkey_hex,
    changeAddress: args.change_address,
    mixOutputAddress: args.mix_output_address,
    bip86Index: args.bip86_index,
    bip86ScanMax: args.bip86_scan_max,
  });
  return unwrap<WraithMixCompleted>(resp).payload;
}

// ----- GSP ---------------------------------------------------------------

export async function gspAuth(): Promise<unknown> {
  return await invoke("gsp_auth");
}

export interface GspSessionStatus {
  have_token: boolean;
  wallet_name: string | null;
  wallet_id: string | null;
  expires_at: number | null;
  remaining_secs: number | null;
  /// "disconnected" / "connecting" / "authenticating" / "authenticated" / "backoff"
  phase: string | null;
  connect_count: number | null;
  last_error: string | null;
}

export async function gspSessionStatus(): Promise<GspSessionStatus> {
  const resp = await invoke("gsp_session_status");
  return unwrap<GspSessionStatus>(resp).payload;
}

// ----- Locks -------------------------------------------------------------

export interface LockEntry {
  lock_id: string;
  capacity_sats: number;
  state: string;
  created_at: number;
  funding_address?: string;
  funding_txid?: string;
  recovery_height?: number;
}

export interface LocksListResponse {
  locks: LockEntry[];
}

export async function locksList(): Promise<LocksListResponse> {
  const resp = await invoke("locks_list");
  return unwrap<LocksListResponse>(resp).payload;
}

export interface LocksPreparedResponse {
  lock_id: string;
  funding_address: string;
  required_sats: number;
}

export async function locksPrepare(
  capacity_sats: number,
): Promise<LocksPreparedResponse> {
  const resp = await invoke("locks_prepare", { capacitySats: capacity_sats });
  return unwrap<LocksPreparedResponse>(resp).payload;
}

export async function locksConfirm(
  lock_id: string,
  funding_txid: string,
): Promise<unknown> {
  return await invoke("locks_confirm", { lockId: lock_id, fundingTxid: funding_txid });
}

export interface LocksRecoveredResult {
  lock_id: string;
  broadcast_txid: string;
  destination: string;
  recovered_sats: number;
  fee_sats: number;
}

export async function locksRecover(
  lock_id: string,
  destination_address: string,
  fee_sats: number,
): Promise<LocksRecoveredResult> {
  const resp = await invoke("locks_recover", {
    lockId: lock_id,
    destinationAddress: destination_address,
    feeSats: fee_sats,
  });
  return unwrap<LocksRecoveredResult>(resp).payload;
}

// ----- PSBT --------------------------------------------------------------

export interface PsbtInputSummary {
  previous_txid: string;
  previous_vout: number;
  /// Sat value of the prevout (witness_utxo or non_witness_utxo).
  /// Null when neither is present in the PSBT — the input is
  /// un-signable in that case (no fee can be computed either).
  value_sats: number | null;
  script_pubkey_hex: string | null;
  address: string | null;
  is_finalized: boolean;
  partial_signatures: number;
  /// True only if the active wallet can sign this input AND it
  /// isn't already finalized. Drives the Sign button's "N inputs
  /// will be signed" hint.
  is_signable_by_active_wallet: boolean;
}

export interface PsbtOutputSummary {
  value_sats: number;
  script_pubkey_hex: string;
  address: string | null;
  /// True when this output goes back to the active wallet's BIP86
  /// receive chain — i.e. it's change rather than a third-party
  /// recipient.
  is_owned_by_active_wallet: boolean;
}

export interface PsbtInspectResponse {
  network: string;
  unsigned_tx_hex: string;
  txid: string;
  inputs: PsbtInputSummary[];
  outputs: PsbtOutputSummary[];
  total_in_sats: number | null;
  total_out_sats: number;
  fee_sats: number | null;
  is_complete: boolean;
  has_signable_inputs: boolean;
}

export async function psbtInspect(psbt: string): Promise<PsbtInspectResponse> {
  const resp = await invoke("psbt_inspect", { psbt });
  return unwrap<PsbtInspectResponse>(resp).payload;
}

export interface PsbtSignResponse {
  /// Updated PSBT, encoded the same way the input was (base64 in →
  /// base64 out, hex in → hex out).
  psbt: string;
  signed_inputs: number[];
  input_count: number;
  is_complete: boolean;
}

export async function psbtSign(
  psbt: string,
  bip86_scan_max?: number,
): Promise<PsbtSignResponse> {
  const resp = await invoke("psbt_sign", { psbt, bip86ScanMax: bip86_scan_max });
  return unwrap<PsbtSignResponse>(resp).payload;
}

export interface PsbtCreateResponse {
  /// Unsigned PSBT, base64.
  psbt: string;
  input_count: number;
  total_input_sats: number;
  recipient_sats: number;
  /// 0 means change was rolled into the fee (residual was < dust).
  change_sats: number;
  fee_sats: number;
  change_bip86_index: number | null;
}

export interface OutpointRef {
  txid: string;
  vout: number;
}

export async function psbtCreate(args: {
  recipient_address: string;
  amount_sats: number;
  fee_rate_sats_per_vb?: number;
  change_index?: number;
  bip86_scan_max?: number;
  /// Coin-control: if set + non-empty, only these outpoints are
  /// considered for selection. Daemon errors if any selected
  /// outpoint is no longer in the wallet's UTXO set.
  selected_outpoints?: OutpointRef[];
}): Promise<PsbtCreateResponse> {
  const resp = await invoke("psbt_create", {
    recipientAddress: args.recipient_address,
    amountSats: args.amount_sats,
    feeRateSatsPerVb: args.fee_rate_sats_per_vb,
    changeIndex: args.change_index,
    bip86ScanMax: args.bip86_scan_max,
    selectedOutpoints: args.selected_outpoints,
  });
  return unwrap<PsbtCreateResponse>(resp).payload;
}

export interface PsbtBroadcastResponse {
  txid: string;
}

export async function psbtBroadcast(
  psbt_or_tx_hex: string,
): Promise<PsbtBroadcastResponse> {
  const resp = await invoke("psbt_broadcast", { psbtOrTxHex: psbt_or_tx_hex });
  return unwrap<PsbtBroadcastResponse>(resp).payload;
}

export interface PsbtBumpFeeResponse {
  /// Unsigned bumped PSBT, base64.
  psbt: string;
  old_fee_sats: number;
  new_fee_sats: number;
  old_change_sats: number;
  new_change_sats: number;
  input_count: number;
}

export async function psbtBumpFee(args: {
  psbt: string;
  new_fee_rate_sats_per_vb: number;
  bip86_scan_max?: number;
}): Promise<PsbtBumpFeeResponse> {
  const resp = await invoke("psbt_bump_fee", {
    psbt: args.psbt,
    newFeeRateSatsPerVb: args.new_fee_rate_sats_per_vb,
    bip86ScanMax: args.bip86_scan_max,
  });
  return unwrap<PsbtBumpFeeResponse>(resp).payload;
}

// ----- Multisig / cosigner ----------------------------------------------

export interface WalletXpubResponse {
  xpub: string;
  master_fingerprint_hex: string;
  path: string;
  /// `[fingerprint/path]xpub.../<0;1>/*` ready to paste into a
  /// `wsh(sortedmulti(...))` or `tr(multi_a(...))` wrapper.
  descriptor_key_fragment: string;
  /// `"mainnet"` or `"testnet"` — what prefix the daemon used.
  network_label: string;
}

export async function walletExportXpub(
  path: string,
  mainnet: boolean,
): Promise<WalletXpubResponse> {
  const resp = await invoke("wallet_export_xpub", { path, mainnet });
  return unwrap<WalletXpubResponse>(resp).payload;
}

// ----- Multisig descriptors ----------------------------------------------

export interface MultisigCosignerSummary {
  fingerprint_hex: string;
  origin_path: string;
  xpub: string;
  /// True when this cosigner is the active wallet.
  is_us: boolean;
}

export interface MultisigDescriptorInspected {
  kind: string;
  k: number;
  n: number;
  cosigners: MultisigCosignerSummary[];
  contains_us: boolean;
  addresses: string[];
  checksum: string | null;
}

export async function multisigDescriptorInspect(
  descriptor: string,
  address_count?: number,
): Promise<MultisigDescriptorInspected> {
  const resp = await invoke("multisig_descriptor_inspect", {
    descriptor,
    addressCount: address_count,
  });
  return unwrap<MultisigDescriptorInspected>(resp).payload;
}

export interface MultisigDescriptorSaved {
  name: string;
  path: string;
}

export async function multisigDescriptorSave(
  name: string,
  descriptor: string,
): Promise<MultisigDescriptorSaved> {
  const resp = await invoke("multisig_descriptor_save", { name, descriptor });
  return unwrap<MultisigDescriptorSaved>(resp).payload;
}

export interface MultisigDescriptorListEntry {
  name: string;
  kind: string;
  k: number;
  n: number;
  cosigner_fingerprints: string[];
}

export interface MultisigDescriptorListResponse {
  descriptors: MultisigDescriptorListEntry[];
}

export async function multisigDescriptorList(): Promise<MultisigDescriptorListResponse> {
  const resp = await invoke("multisig_descriptor_list");
  return unwrap<MultisigDescriptorListResponse>(resp).payload;
}

export interface MultisigDescriptorAddressEntry {
  index: number;
  address: string;
}

export interface MultisigDescriptorAddressesResponse {
  name: string;
  internal: boolean;
  addresses: MultisigDescriptorAddressEntry[];
}

export async function multisigDescriptorAddresses(args: {
  name: string;
  start_index?: number;
  count?: number;
  internal?: boolean;
}): Promise<MultisigDescriptorAddressesResponse> {
  const resp = await invoke("multisig_descriptor_addresses", {
    name: args.name,
    startIndex: args.start_index,
    count: args.count,
    internal: args.internal,
  });
  return unwrap<MultisigDescriptorAddressesResponse>(resp).payload;
}

export async function multisigDescriptorDelete(name: string): Promise<{
  removed: boolean;
}> {
  const resp = await invoke("multisig_descriptor_delete", { name });
  return unwrap<{ removed: boolean }>(resp).payload;
}

// ----- Live BIP-352 receive notifications --------------------------------

/// Start the daemon push-watch subscription. The Tauri side keeps a
/// long-lived IPC connection and forwards each `PaymentDetected`
/// frame to the frontend as a `wraith://payment-detected` event.
/// Idempotent — the Rust side's atomic guard makes repeat calls a
/// no-op, so the safest pattern is to call it once on app mount and
/// once more on any reconnect.
export async function startWatch(): Promise<void> {
  await invoke("start_watch");
}

export interface DetectedPayment {
  txid: string;
  block_height: number | null;
  vout: number;
  amount_sats: number;
  k: number;
  received_at: number;
}

/// Subscribe to live payment detections. Returns an unlisten fn —
/// call it from the effect's cleanup. Pair with `startWatch()` once
/// at app boot.
export async function onPaymentDetected(
  cb: (p: DetectedPayment) => void,
): Promise<UnlistenFn> {
  return listen<DetectedPayment>("wraith://payment-detected", (event) => {
    cb(event.payload);
  });
}

export interface WatchError {
  message: string;
}

/// Subscribe to watch-loop terminal errors (daemon socket closed,
/// IPC parse failure, etc.). The Tauri side restarts the loop on
/// `startWatch()` next time the GUI calls it.
export async function onWatchError(
  cb: (e: WatchError) => void,
): Promise<UnlistenFn> {
  return listen<WatchError>("wraith://watch-error", (event) => {
    cb(event.payload);
  });
}
