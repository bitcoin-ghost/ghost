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
  /// The node the wallet reads and writes the chain through. `null` when
  /// none is configured, in which case chain operations refuse.
  ghostd_url: string | null;
  /// "cookie" | "userpass" | "none" — never the credential itself.
  ghostd_auth: string;
  /// True when WRAITHD_GHOSTD_URL pins the node at boot. The selector is
  /// shown read-only and the daemon refuses changes while it holds.
  ghostd_env_override?: boolean;
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

/// Localhost default for someone running their own node.
export const OWN_NODE_RPC_DEFAULT = "http://127.0.0.1:8332";

export interface NodeResult {
  ghostd_url: string | null;
  /** "cookie" | "userpass" | "none" — never the credential itself. */
  auth: string;
  env_pinned: boolean;
}

/// Point the wallet at your node.
///
/// Passing nothing clears it, after which the wallet refuses chain
/// operations — deliberately, rather than falling back to somebody else's
/// node and reading your balance over their shoulder.
export async function setNode(args: {
  ghostd_url?: string;
  cookie_path?: string;
  user?: string;
  pass?: string;
}): Promise<NodeResult> {
  const resp = await invoke("set_node", {
    ghostdUrl: args.ghostd_url,
    cookiePath: args.cookie_path,
    user: args.user,
    pass: args.pass,
  });
  return unwrap<NodeResult>(resp).payload;
}

export interface ChainStatusResponse {
  backend_version: string;
  network: string;
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

/// Consolidated connectivity snapshot for the header status bar.
/// Composed daemon-side from the ghost-pay probe + GSP session + chain
/// fields, so the GUI makes ONE call and — crucially — this never
/// throws for an unreachable backend: `ghost_pay_reachable: false` is a
/// normal, renderable result, not an error. That's what fixes the
/// "constantly refreshing, no response" feel when a laptop has no
/// local ghost-pay/GSP.
export interface ConnectionStatusResponse {
  network: string;
  /// Whether a node is set at all. Distinct from `node_reachable`: not
  /// configured and configured-but-silent are different problems with
  /// different fixes, and the header must not merge them.
  node_configured: boolean;
  node_reachable: boolean;
  node_version: string | null;
  node_error: string | null;
  chain_height: number | null;
  chain_headers: number | null;
  chain_synced: boolean;
}

export async function connectionStatus(): Promise<ConnectionStatusResponse> {
  const resp = await invoke("connection_status");
  return unwrap<ConnectionStatusResponse>(resp).payload;
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

/**
 * Create a wallet.
 *
 * `userEntropyDigest` is the hex digest of dice or coin flips the user rolled,
 * mixed into the seed alongside the operating system's randomness and never
 * used instead of it — so supplying none costs nothing, and supplying some can
 * only raise the floor. Omitted until the dice screen lands (#705).
 */
export async function walletCreate(
  name: string,
  passphrase: string,
  userEntropyDigest?: string,
): Promise<WalletCreateResult> {
  const resp = await invoke("wallet_create", {
    name,
    passphrase,
    userEntropyDigest,
  });
  return unwrap<WalletCreateResult>(resp).payload;
}

/// Restore a wallet from its 24 words.
///
/// `birthHeight` is the chain height the seed was first used at. The block
/// scanner reads forward from there to rebuild the history; without it,
/// scanning starts at the tip and nothing this seed did before now appears —
/// the coins are all still found, but what they did is not. Guessing low is
/// safe and slow; guessing high loses history silently.
export async function walletImport(
  name: string,
  mnemonic: string,
  passphrase: string,
  birthHeight?: number,
): Promise<{ name: string; path: string }> {
  const resp = await invoke("wallet_import", {
    name,
    mnemonic,
    passphrase,
    birthHeight,
  });
  return unwrap<{ name: string; path: string }>(resp).payload;
}

export async function walletShowMnemonic(
  name: string,
  passphrase: string,
): Promise<{ name: string; mnemonic: string }> {
  const resp = await invoke("wallet_show_mnemonic", { name, passphrase });
  return unwrap<{ name: string; mnemonic: string }>(resp).payload;
}

// These three unwrap() so a daemon Response::Error (e.g. wrong passphrase) THROWS
// rather than resolving as { result: "error" } — otherwise the caller's success
// path runs and the failure is silently swallowed (no error shown to the user).
export async function walletUnlock(
  name: string,
  passphrase: string,
): Promise<unknown> {
  const resp = await invoke("wallet_unlock", { name, passphrase });
  return unwrap(resp).payload;
}

export interface WalletBackupResult {
  name: string;
  /// Absolute path the daemon wrote / read.
  path: string;
  /// Size of the encrypted keystore copied, in bytes.
  bytes: number;
}

/// Back up wallet `name`'s encrypted keystore to `to_path`. The daemon
/// copies the on-disk keystore (still encrypted) and refuses to
/// overwrite an existing file.
export async function walletExport(
  name: string,
  to_path: string,
): Promise<WalletBackupResult> {
  const resp = await invoke("wallet_export", { name, toPath: to_path });
  return unwrap<WalletBackupResult>(resp).payload;
}

/// Restore wallet `name` from an exported keystore at `from_path`. The
/// daemon refuses if a wallet of that name already exists on disk.
export async function walletRestore(
  name: string,
  from_path: string,
): Promise<WalletBackupResult> {
  const resp = await invoke("wallet_restore", { name, fromPath: from_path });
  return unwrap<WalletBackupResult>(resp).payload;
}

export interface CheckForUpdateResult {
  current_version: string;
  /// Version from the fetched manifest, when fetch + parse succeeded.
  latest_version: string | null;
  /// True only when the manifest version byte-equals the running one.
  up_to_date: boolean;
  /// Where the manifest was fetched from (resolved override or the
  /// daemon-configured default).
  manifest_url: string;
  tarball: string | null;
  tarball_sha256: string | null;
}

/// Ask the daemon to fetch a release manifest and compare its version
/// against the running daemon. Pass `manifest_url` to override the
/// daemon-configured default. The daemon only reports — it never
/// downloads or installs.
export async function checkForUpdate(
  manifest_url?: string,
): Promise<CheckForUpdateResult> {
  const resp = await invoke("check_for_update", { manifestUrl: manifest_url });
  return unwrap<CheckForUpdateResult>(resp).payload;
}

export async function walletLock(name: string | null): Promise<unknown> {
  const resp = await invoke("wallet_lock", { name });
  return unwrap(resp).payload;
}

export async function walletSelect(name: string): Promise<unknown> {
  const resp = await invoke("wallet_select", { name });
  return unwrap(resp).payload;
}

/// Permanently delete a wallet: the daemon removes its on-disk
/// keystore + data directory and drops it from the unlocked set.
/// Irreversible — callers must confirm with the user first.
export async function walletDelete(
  name: string,
): Promise<{ name: string }> {
  const resp = await invoke("wallet_delete", { name });
  return unwrap<{ name: string }>(resp).payload;
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

// ----- Wallet balance, coins and history ---------------------------------

export interface LightBalanceResponse {
  /// Confirmed on-chain balance, in sats. `null` when it could not be read.
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
  /** null = the wallet has no record of the amount; not the same as zero. */
  amount_sats: number | null;
  fee_sats: number | null;
  tx_type: string;
  /** null = the backend cannot say; not the same as zero confirmations. */
  confirmations: number | null;
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

// `ghostpay` is the only real Send mode — the instant L2 ledger
// transfer. The former `wraith`/`confidential` values were cosmetic:
// they took the same plaintext L2 path, so the daemon now rejects
// them. Unlinkable L1 spends live in the Mix flow, not Send.
export type LightSendMode = "ghostpay";

export async function lightSend(
  recipient: string,
  amount_sats: number,
  mode: LightSendMode = "ghostpay",
  memo?: string,
  shroud_max_ms?: number,
): Promise<unknown> {
  const resp = await invoke("light_send", {
    recipient,
    amountSats: amount_sats,
    mode,
    memo,
    shroudMaxMs: shroud_max_ms,
  });
  // Must unwrap: the daemon serializes a rejected payment as
  // { result: "error", message }, which `invoke` RESOLVES. Without unwrap the
  // caller's success branch runs and the UI falsely reports "Sent". unwrap()
  // throws on result:"error" so Send.tsx's catch surfaces the real failure.
  return unwrap(resp).payload;
}

export interface L1SendResponse {
  txid: string;
  recipient: string;
  amount_sats: number;
  fee_sats: number;
  change_sats: number;
  input_count: number;
  shroud_delay_ms?: number | null;
}

/// Build, sign and broadcast an on-chain payment in one call.
///
/// `recipient_address` takes a Bitcoin address, or a Ghost ID for a silent
/// payment — which pays a fresh taproot output only the recipient can find,
/// announced by an OP_RETURN carrying the ephemeral key. That hides who was
/// paid, not that a payment happened.
///
/// The PSBT verbs remain for anyone who wants to look at the transaction
/// before it leaves; this is the ordinary path.
export async function l1Send(args: {
  recipient_address: string;
  amount_sats: number;
  fee_rate_sats_per_vb?: number;
  change_index?: number;
  bip86_scan_max?: number;
  selected_outpoints?: OutpointRef[];
  memo?: string;
  shroud_max_ms?: number;
}): Promise<L1SendResponse> {
  const resp = await invoke("l1_send", {
    recipientAddress: args.recipient_address,
    amountSats: args.amount_sats,
    feeRateSatsPerVb: args.fee_rate_sats_per_vb,
    changeIndex: args.change_index,
    bip86ScanMax: args.bip86_scan_max,
    selectedOutpoints: args.selected_outpoints,
    memo: args.memo,
    shroudMaxMs: args.shroud_max_ms,
  });
  // Must unwrap: a rejected send serializes as { result: "error", message },
  // which `invoke` RESOLVES. Without this the caller's success branch runs and
  // the UI reports "Sent" for a payment that never left.
  return unwrap<L1SendResponse>(resp).payload;
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
  service_fee_sats: number;
  mix_seat_price_sats: number;
  jump_seat_price_sats: number;
}

export interface WraithDiscoverResult {
  /// Coordinator URL that actually answered (may differ from the
  /// requested `coordinator_url` if the call rotated through
  /// `coordinator_peers`).
  answered_by: string;
  network: string;
  pool_id: string;
  service_fee_bps: number;
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

export interface WraithResolveResult {
  /** Elected coordinator endpoint to dial for the tier, or null when the
   *  election is off/pending/unadvertised (caller keeps the manual URL). */
  endpoint: string | null;
  /** Election epoch the resolution was sharded on, when known. */
  epoch: number | null;
}

/**
 * Resolve the network-elected coordinator endpoint for a mixing tier from the
 * node's decentralised election (fetched through ghost-pay). Wallets sharing a
 * (tier, epoch) converge on the same seat for a larger anonymity set.
 */
export async function wraithResolveCoordinator(
  tier_id: string,
): Promise<WraithResolveResult> {
  const resp = await invoke("wraith_resolve_coordinator", { tierId: tier_id });
  return unwrap<WraithResolveResult>(resp).payload;
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
  utxo_txid: string;
  utxo_vout: number;
  utxo_value_sats: number;
  utxo_scriptpubkey_hex: string;
  mix_output_address: string;
  bip86_index?: number;
  bip86_scan_max?: number;
  /// Smallest anonymity set, in distinct entities, worth signing into.
  /// Omitted uses the wallet's default. Supplying a lower value is how a user
  /// accepts a smaller set — a stated number rather than a dismissed dialog.
  min_entities?: number;
}

/// The wallet's own count of a round. Derived from the chain by the wallet,
/// never taken from the coordinator.
export interface AnonymitySetReport {
  seats: number;
  entities: number;
  discounted: number;
  unverified: number;
  payers: number;
}

/// The wallet inspected the round and refused to sign it.
export interface WraithMixRefused {
  session_id: string;
  report: AnonymitySetReport;
  reasons: string[];
  min_entities: number;
  /// Whether accepting a smaller set could make this round signable.
  ///
  /// False for an over-claim: the coordinator stated a figure the chain does
  /// not support, and no floor makes that acceptable. The UI must not offer to
  /// lower one in that case.
  lowering_the_floor_would_help: boolean;
}

/// A mix either completed or was refused. The refusal is not an error — it is
/// the wallet doing its job, and it carries what the user needs to decide.
export type WraithMixResult =
  | { kind: "completed"; value: WraithMixCompleted }
  | { kind: "refused"; value: WraithMixRefused };

/// One-shot Wraith Lite CoinJoin. Daemon enrols, signs the
/// taproot key-path witness using the active wallet's BIP86
/// keystore, and drives the round to broadcast.
export async function wraithMixRun(
  args: WraithMixRunArgs,
): Promise<WraithMixResult> {
  const resp = await invoke("wraith_mix_run", {
    coordinatorUrl: args.coordinator_url,
    coordinatorPeers: args.coordinator_peers ?? [],
    socks5Proxy: args.socks5_proxy,
    tierId: args.tier_id,
    ghostId: args.ghost_id,
    utxoTxid: args.utxo_txid,
    utxoVout: args.utxo_vout,
    utxoValueSats: args.utxo_value_sats,
    utxoScriptpubkeyHex: args.utxo_scriptpubkey_hex,
    mixOutputAddress: args.mix_output_address,
    bip86Index: args.bip86_index,
    bip86ScanMax: args.bip86_scan_max,
    minEntities: args.min_entities,
  });
  // The daemon distinguishes the two by response variant. A refusal arriving
  // as a thrown error would lose the report, which is the only part the user
  // can act on.
  const payload = unwrap<Record<string, unknown>>(resp).payload;
  if (payload && typeof payload === "object" && "reasons" in payload) {
    return { kind: "refused", value: payload as unknown as WraithMixRefused };
  }
  return { kind: "completed", value: payload as unknown as WraithMixCompleted };
}

// ----- Ghost Lock lanes ---------------------------------------------------

/// One lane of a Ghost Lock.
export interface GhostLockLane {
  kind: string;
  label: string;
  address: string;
  /// Confirmed — what has settled.
  balance_sats: number;
  /// Unconfirmed. Shown beside the settled figure, never added to it.
  pending_sats: number;
  /// True only for Investments: the quorum can move these funds without you.
  quorum_can_spend_alone: boolean;
  /// False for Cash — those coins are already public, so a round gains nothing.
  round_eligible: boolean;
}

export interface GhostLockLanes {
  lanes: GhostLockLane[];
  total_sats: number;
  total_pending_sats: number;
  /// Of the settled total, how much the quorum could move without you.
  custodial_sats: number;
  chain_height: number;
}

export interface GhostLockLanesArgs {
  backup_pubkey: string;
  heir_pubkey: string;
  quorum_pubkey: string;
  inherit_height: number;
  anchor_height: number;
  bip86_index?: number;
}

/// A remembered Lock definition.
export interface GhostLockRecord {
  lock_id: string;
  label: string | null;
  backup_pubkey: string;
  heir_pubkey: string;
  quorum_pubkey: string;
  anchor_height: number;
  inherit_height: number;
  bip86_index: number;
}

/// Remember a Lock. Saving the same keys twice updates one record — the id is
/// derived from the fields, so re-entering them is a rename, not a duplicate.
export async function ghostLockSave(args: {
  label?: string;
  backup_pubkey: string;
  heir_pubkey: string;
  quorum_pubkey: string;
  anchor_height: number;
  inherit_height: number;
  bip86_index?: number;
}): Promise<{ lock: GhostLockRecord; created: boolean }> {
  const resp = await invoke("ghost_lock_save", {
    label: args.label,
    backupPubkey: args.backup_pubkey,
    heirPubkey: args.heir_pubkey,
    quorumPubkey: args.quorum_pubkey,
    anchorHeight: args.anchor_height,
    inheritHeight: args.inherit_height,
    bip86Index: args.bip86_index,
  });
  return unwrap<{ lock: GhostLockRecord; created: boolean }>(resp).payload;
}

export async function ghostLockList(): Promise<GhostLockRecord[]> {
  const resp = await invoke("ghost_lock_list");
  return unwrap<{ locks: GhostLockRecord[] }>(resp).payload.locks;
}

/// Forget a definition. The funds are untouched — the lanes stay spendable by
/// anyone holding the keys.
export async function ghostLockForget(
  lockId: string,
): Promise<{ lock_id: string; existed: boolean }> {
  const resp = await invoke("ghost_lock_forget", { lockId });
  return unwrap<{ lock_id: string; existed: boolean }>(resp).payload;
}

/// Derive a Ghost Lock's four lanes and read their balances.
///
/// The MuSig2 aggregates are derived by the daemon from these three keys.
/// BIP-327 key aggregation is deterministic, so no ceremony is needed to build a
/// Lock; interaction is required only to sign a key-path spend.
export async function ghostLockLanes(
  args: GhostLockLanesArgs,
): Promise<GhostLockLanes> {
  const resp = await invoke("ghost_lock_lanes", {
    backupPubkey: args.backup_pubkey,
    heirPubkey: args.heir_pubkey,
    quorumPubkey: args.quorum_pubkey,
    inheritHeight: args.inherit_height,
    anchorHeight: args.anchor_height,
    bip86Index: args.bip86_index,
  });
  return unwrap<GhostLockLanes>(resp).payload;
}

/// Where a round should pay to fund one lane privately.
export interface GhostLockRoundDestination {
  lock_id: string;
  /// The lane, echoed back so a caller cannot mistake which one it asked for.
  lane: string;
  label: string;
  /// The address a round must pay into — the lane itself.
  address: string;
}

/// Ask where a round should pay to fund one lane — private entry.
///
/// Two ways to put money in a lane, and they are not equivalent:
///
/// - **Directly.** Simple, works today, and publishes the link between coins
///   you are known to control and this Lock, permanently.
/// - **Through a round.** The round's output IS the lane, so on-chain the
///   deposit looks like any other round output and nothing ties it to you.
///
/// Cash is refused by the daemon: it is public by design, so a round would buy
/// unlinkability the lane discards the moment the coin lands.
export async function ghostLockRoundDestination(
  lockId: string,
  lane: string,
): Promise<GhostLockRoundDestination> {
  const resp = await invoke("ghost_lock_round_destination", { lockId, lane });
  return unwrap<GhostLockRoundDestination>(resp).payload;
}

/// A coin in a lane, and whether its escape has matured.
export interface EscapeCoin {
  txid: string;
  vout: number;
  sats: number;
  confirmations: number;
  /// Blocks still to wait. Zero means spendable now.
  blocks_remaining: number;
}

/// What an escape spend needs.
export interface GhostLockEscapePlan {
  lock_id: string;
  lane: string;
  escape: string;
  delay_blocks: number;
  /// Every spending input must carry this nSequence. A different value is
  /// rejected by the network as non-final.
  required_sequence: number;
  lane_address: string;
  coins: EscapeCoin[];
}

export interface GhostLockEscapeSigned {
  lock_id: string;
  lane: string;
  escape: string;
  psbt: string;
  /// The finished transaction, ready to broadcast.
  tx_hex: string;
}

/// Ask what leaving alone needs, before building the transaction.
export async function ghostLockEscapePlan(
  lockId: string,
  lane: string,
): Promise<GhostLockEscapePlan> {
  const resp = await invoke("ghost_lock_escape_plan", { lockId, lane });
  return unwrap<GhostLockEscapePlan>(resp).payload;
}

/// Sign a lane's escape leaf. No quorum, no device, no ceremony.
export async function ghostLockEscapeSign(args: {
  lockId: string;
  lane: string;
  psbt: string;
  inputIndex: number;
}): Promise<GhostLockEscapeSigned> {
  const resp = await invoke("ghost_lock_escape_sign", {
    lockId: args.lockId,
    lane: args.lane,
    psbt: args.psbt,
    inputIndex: args.inputIndex,
  });
  return unwrap<GhostLockEscapeSigned>(resp).payload;
}

/// One output of a spend, as a person reads it.
export interface LockSpendOutput {
  address: string | null;
  sats: number;
}

/// What a spend does. Derived by the daemon from the same transaction it
/// derives the sighash from, so the figures shown and the thing signed cannot
/// diverge.
export interface LockSpendSummary {
  input_index: number;
  input_sats: number;
  input_address: string | null;
  outputs: LockSpendOutput[];
  fee_sats: number;
  input_count: number;
}

export interface GhostLockSignBegun {
  session: string;
  summary: LockSpendSummary;
  /// JSON to carry to the offline device. Contains the whole PSBT, so the
  /// device recomputes the sighash rather than being told it.
  device_request: string;
  our_nonce: string;
}

export interface GhostLockSignNonced {
  session: string;
  device_request: string;
}

export interface GhostLockSigned {
  session: string;
  signature: string;
  psbt: string;
}

/// Round 1: review the spend and commit this wallet's nonce.
export async function ghostLockSignBegin(args: {
  lockId: string;
  lane: string;
  psbt: string;
  inputIndex: number;
}): Promise<GhostLockSignBegun> {
  const resp = await invoke("ghost_lock_sign_begin", {
    lockId: args.lockId,
    lane: args.lane,
    psbt: args.psbt,
    inputIndex: args.inputIndex,
  });
  return unwrap<GhostLockSignBegun>(resp).payload;
}

/// Round 1 reply. The daemon signs its own share here, burning its nonce
/// durably first — so no secret nonce is held while you carry the second
/// payload to the device.
export async function ghostLockSignNonce(
  session: string,
  deviceNonce: string,
): Promise<GhostLockSignNonced> {
  const resp = await invoke("ghost_lock_sign_nonce", {
    session,
    deviceNonce,
  });
  return unwrap<GhostLockSignNonced>(resp).payload;
}

/// Round 2 reply. Completes the spend.
export async function ghostLockSignComplete(
  session: string,
  devicePartial: string,
): Promise<GhostLockSigned> {
  const resp = await invoke("ghost_lock_sign_complete", {
    session,
    devicePartial,
  });
  return unwrap<GhostLockSigned>(resp).payload;
}

// ----- Locks -------------------------------------------------------------

// Must match the wire `LockEntry` in ipc/src/lib.rs exactly. The fields are read
// from an `unknown` cast, so a name mismatch is invisible to tsc but breaks at
// runtime — previously `state`/`created_at`/`recovery_height` (none of which exist
// on the wire) left the State pill blank and the Confirm/Recover buttons (gated on
// `state`) permanently unreachable.













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

export interface DetectedPaymentEntry {
  txid: string;
  vout: number;
  amount_sats: number | null;
  block_height: number | null;
  /** The sender's derivation index — what makes the coin spendable. */
  k: number;
  received_at: number;
}

/// Silent payments the block scanner has found.
///
/// These are absent from `lightUtxos`: a silent payment lands on a key derived
/// from the sender's ephemeral key and this wallet's Ghost ID, not on an
/// address the wallet published, so a scan of derived addresses cannot see it.
export async function lightDetected(): Promise<DetectedPaymentEntry[]> {
  const resp = await invoke("light_detected");
  return unwrap<{ detections: DetectedPaymentEntry[] }>(resp).payload.detections;
}

// ----- Noticing money arriving -------------------------------------------

/// One coin the wallet did not have last time it looked.
export interface DetectedPayment {
  txid: string;
  vout: number;
  amount_sats: number;
  confirmations: number;
  /// When the wallet noticed, unix epoch seconds. Not when it was paid —
  /// polling cannot know that, and pretending otherwise would put a wrong
  /// timestamp on a receipt.
  noticed_at: number;
}

/// Watch for coins arriving, by asking the node.
///
/// # Why polling
///
/// This used to be a push: the operator's GSP scanned the chain on the
/// wallet's behalf and told it what had landed. That is gone with the rest of
/// L2, and it was never free — it meant handing somebody a scan key and
/// trusting them with the answer.
///
/// So the wallet asks its own node instead, on an interval, and reports coins
/// it had not seen before. The cost is latency: a payment shows up within one
/// poll rather than the instant it is relayed. The gain is that nobody else
/// has to know the wallet is watching.
///
/// The first poll establishes the baseline and reports nothing — otherwise
/// every coin already in the wallet would arrive as a notification the moment
/// a screen opened.
///
/// Returns a function that stops the watch; call it from an effect's cleanup.
export function watchForPayments(
  cb: (p: DetectedPayment) => void,
  opts: { intervalMs?: number; scanMaxIndex?: number } = {},
): () => void {
  const intervalMs = opts.intervalMs ?? 15_000;
  const scanMaxIndex = opts.scanMaxIndex ?? 32;
  let stopped = false;
  // `null` until the first successful poll, which is what distinguishes
  // "nothing seen yet" from "nothing there" — an empty Set on a failed first
  // poll would announce the whole wallet on the second.
  let seen: Set<string> | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const key = (u: { txid: string; vout: number }) => `${u.txid}:${u.vout}`;

  const tick = async () => {
    try {
      // Zero confirmations: a payment in the mempool is the one the user is
      // standing there waiting for.
      const r = await lightL1Utxos(scanMaxIndex, 0);
      const now = new Set(r.utxos.map(key));
      if (seen === null) {
        seen = now;
      } else {
        for (const u of r.utxos) {
          if (!seen.has(key(u))) {
            cb({
              txid: u.txid,
              vout: u.vout,
              amount_sats: u.amount_sats,
              confirmations: u.confirmations,
              noticed_at: Math.floor(Date.now() / 1000),
            });
          }
        }
        seen = now;
      }
    } catch {
      // An unreachable node is not a reason to stop watching, and it is
      // reported by the status header already. Keep the baseline: dropping it
      // would replay every coin as new when the node comes back.
    }
    if (!stopped) timer = setTimeout(tick, intervalMs);
  };
  void tick();

  return () => {
    stopped = true;
    if (timer !== undefined) clearTimeout(timer);
  };
}
