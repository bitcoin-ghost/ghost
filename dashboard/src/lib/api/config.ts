// Config API endpoints
import { fetchApi } from './client';
import type { NodeConfig, FullNodeConfig, L2PruningConfig } from '@/types/api';

export async function getConfig(): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config');
}

export async function getFullConfig(): Promise<FullNodeConfig> {
  return fetchApi<FullNodeConfig>('/api/v1/config/full');
}

// Operator Window (OW) = storage.prune_height. The one editable pruning-depth
// knob; the backend persists it and clamps a non-zero depth up to the Validator
// Window floor.
export async function setOperatorWindow(blocks: number): Promise<{ success: boolean; window: number }> {
  return fetchApi<{ success: boolean; window: number }>('/api/v1/config/operator_window', {
    method: 'POST',
    body: JSON.stringify({ blocks }),
  });
}

// L2 Pruning status (from ghost-pay-node)
export async function getL2PruningStatus(): Promise<L2PruningConfig> {
  return fetchApi<L2PruningConfig>('/api/v1/ghost-pay/pruning');
}

export async function setGhostMode(enabled: boolean): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/ghost_mode', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

// Ghost Mode local egress: while ghost mode is on, still announce and serve our
// OWN (locally-submitted) transactions so a connected wallet can reach miners,
// while peer-received transactions stay fully suppressed. Toggles live.
export async function setGhostModeLocalEgress(enabled: boolean): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/ghost_mode_local_egress', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

// Result of toggling ghostd Tor mode. The apply happens off the request path
// (ghostd restarts, then the pool bounces); poll the reaper GET's ghostd_apply
// for the terminal state.
export interface TorToggleResult {
  success: boolean;
  enabled: boolean;
  ghostd_apply?: GhostdApplyStatus;
  message: string;
}

// Toggle ghostd Tor mode (-tormode). Persists [node_launch].tor_mode to
// pool.toml, regenerates ghostd's launch-flag drop-in and restarts ghostd, then
// bounces ghost-pool. Requires a restart because -tormode is a startup flag.
export async function setTor(enabled: boolean): Promise<TorToggleResult> {
  return fetchApi<TorToggleResult>('/api/v1/config/tor', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

// ghostd daemon / node launch settings (pool.toml [node_launch]). Every field
// maps to a ghostd startup flag, so a change requires a ghostd restart. A field
// left undefined/null clears the flag (reverts to ghostd's own default).
export interface DaemonSettings {
  // Mempool
  max_mempool_mb?: number | null;       // -maxmempool (MB)
  mempool_expiry_hours?: number | null; // -mempoolexpiry (hours)
  // Full RBF (-mempoolfullrbf). ghostd defaults to full RBF ON (any tx
  // replaceable). false opts out → -mempoolfullrbf=0 (only BIP125-signalling
  // txs replaceable). null/true preserve ghostd's default (emit nothing).
  full_rbf?: boolean | null;
  // Connectivity
  max_connections?: number | null;      // -maxconnections
  max_upload_target_mb?: string | null; // -maxuploadtarget (number + optional unit k|K|m|M|g|G|t|T; 0 = no limit)
  // Performance
  dbcache_mb?: number | null;           // -dbcache (MB)
  // Indexes / BIP157
  block_filter_index?: boolean | null;  // -blockfilterindex=1 (triggers an index build)
  peer_block_filters?: boolean | null;  // -peerblockfilters=1 (requires block_filter_index)
  // Privacy networking
  onlynet?: string[];                    // -onlynet (repeated): ipv4|ipv6|onion|i2p|cjdns
  i2p_sam?: string | null;               // -i2psam host:port
  i2p_accept_incoming?: boolean | null;  // -i2pacceptincoming=1 (needs i2p_sam)
}

export interface DaemonConfigResponse {
  settings: DaemonSettings;
  ghostd_apply?: GhostdApplyStatus;
  message: string;
}

export interface DaemonUpdateResponse {
  success: boolean;
  restart_pending?: boolean;
  ghostd_apply?: GhostdApplyStatus;
  message: string;
}

export async function getDaemonSettings(): Promise<DaemonConfigResponse> {
  return fetchApi<DaemonConfigResponse>('/api/v1/config/daemon');
}

// Persist [node_launch] daemon settings and apply them: ghostd's launch-flag
// drop-in is regenerated and ghostd is RESTARTED, then ghost-pool bounces.
export async function setDaemonSettings(settings: DaemonSettings): Promise<DaemonUpdateResponse> {
  return fetchApi<DaemonUpdateResponse>('/api/v1/config/daemon', {
    method: 'POST',
    body: JSON.stringify(settings),
  });
}

export async function setArchiveMode(enabled: boolean): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/archive_mode', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

export async function setPublicMiningConfig(enabled: boolean): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/public_mining', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

// Per-vector Ghost Reaper configuration. Field names match pool.toml [reaper].
export interface ReaperSettings {
  enabled: boolean;
  // Shared (pool template reaper + ghostd mempool reaper)
  reject_inscription: boolean;
  reject_dropstuffing: boolean;
  reject_fakepubkey: boolean;
  reject_annex: boolean;
  // Node-only (ghostd mempool reaper)
  reject_opreturn: boolean;
  reject_runestone: boolean;
  reject_dustflood: boolean;
  // Pool-only (template reaper)
  reject_unreachable_code: boolean;
  reject_excess_witness: boolean;
  reject_legacy_data_stuffing: boolean;
  validate_pubkey_curve_point: boolean;
  // Thresholds
  max_op_return_bytes: number;
  min_drop_size: number;
  // Must match the Rust field name `dust_flood_threshold` (ghost_common::config::ReaperSettings);
  // a mismatched key is silently dropped by serde, so the threshold never reaches the node.
  dust_flood_threshold: number;
  min_excess_witness_bytes: number;
  legacy_max_push_bytes: number;
}

// Terminal result of the node's last automatic ghostd mempool-reaper apply.
// state: "idle" | "applying" | "applied" | "failed" | "skipped".
export interface GhostdApplyStatus {
  state: string;
  message: string;
  updated_at: number;
}

export interface ReaperConfigResponse {
  enabled: boolean;
  mode: string;
  settings: ReaperSettings;
  ghostd_apply?: GhostdApplyStatus;
  message: string;
}

export interface ReaperUpdateResponse {
  success: boolean;
  persisted: boolean;
  enabled: boolean;
  // The ghostd mempool reaper is now applied automatically after each save;
  // this is always false and kept only for backwards compatibility.
  ghostd_restart_required?: boolean;
  // Status of the automatic ghostd apply the save kicked off (state is
  // "applying" while in flight; poll the reaper GET for the terminal result).
  ghostd_apply?: GhostdApplyStatus;
  message: string;
}

export async function getReaper(): Promise<ReaperConfigResponse> {
  return fetchApi<ReaperConfigResponse>('/api/v1/config/reaper');
}

// All-detectors-on defaults, matching pool.toml's [reaper] serde defaults.
export const REAPER_DEFAULTS: ReaperSettings = {
  enabled: true,
  reject_inscription: true,
  reject_dropstuffing: true,
  reject_fakepubkey: true,
  reject_annex: true,
  reject_opreturn: true,
  reject_runestone: true,
  reject_dustflood: true,
  reject_unreachable_code: true,
  reject_excess_witness: true,
  reject_legacy_data_stuffing: true,
  validate_pubkey_curve_point: true,
  max_op_return_bytes: 82,
  min_drop_size: 76,
  dust_flood_threshold: 330,
  min_excess_witness_bytes: 500,
  legacy_max_push_bytes: 80,
};

// Accepts the full per-vector settings, or a bare boolean for a coarse
// master on/off toggle (per-vector defaults to all-on).
export async function setReaper(input: ReaperSettings | boolean): Promise<ReaperUpdateResponse> {
  const settings: ReaperSettings =
    typeof input === 'boolean' ? { ...REAPER_DEFAULTS, enabled: input } : input;
  return fetchApi<ReaperUpdateResponse>('/api/v1/config/reaper', {
    method: 'POST',
    body: JSON.stringify(settings),
  });
}

// The REAL tier policy (pool.toml [policy].profile). This actually governs which
// BUDS tiers get mined. Writing it persists to pool.toml and triggers a graceful
// restart to apply.
export type PolicyProfileType = 'strict' | 'permissive' | 'full_open';

export interface PolicyProfileResult {
  success: boolean;
  profile: PolicyProfileType;
  restart_pending: boolean;
}

export async function setPolicyProfile(profile: PolicyProfileType): Promise<PolicyProfileResult> {
  return fetchApi<PolicyProfileResult>('/api/v1/config/policy_profile', {
    method: 'POST',
    body: JSON.stringify({ profile }),
  });
}

// The block-priority lever (pool.toml [pool].block_priority). Governs how the
// block template is ORDERED — either by max fee (revenue) or by seating BUDS
// financial txs (T0/T1) ahead of data txs (T2/T3). It never adds or drops txs
// (permutation only), so it is weight-safe. Writing it persists to pool.toml and
// triggers a graceful restart to apply.
export type BlockPriorityType = 'max_fee' | 'payments_first';

export interface BlockPriorityResult {
  success: boolean;
  block_priority: BlockPriorityType;
  restart_pending: boolean;
}

export async function setBlockPriority(
  blockPriority: BlockPriorityType,
): Promise<BlockPriorityResult> {
  return fetchApi<BlockPriorityResult>('/api/v1/config/block_priority', {
    method: 'POST',
    body: JSON.stringify({ block_priority: blockPriority }),
  });
}

// Map a setup-wizard's coarse mempool-policy choice onto the REAL tier-policy
// profile. The wizards present simplified labels ("standard"/permissive vs
// "strict"); anything more permissive than strict maps to `full_open`.
export function toPolicyProfile(choice: string): PolicyProfileType {
  switch (choice) {
    case 'strict':
      return 'strict';
    case 'full_open':
    case 'max_fee':
      return 'full_open';
    default:
      // "standard" / "permissive" and any unknown value default to permissive.
      return 'permissive';
  }
}

// The full custom tier policy (pool.toml [policy].custom). Writing it sets
// [policy].profile = custom, persists every field, and triggers a graceful
// restart to apply. This is the advanced counterpart to the three presets: it
// exposes every per-field knob the block builder now enforces.
export interface PolicyCustomConfig {
  // Per-tier inclusion (T0 financial .. T3 heavy data).
  allow_t0: boolean;
  allow_t1: boolean;
  allow_t2: boolean;
  allow_t3: boolean;
  // Content-type toggles.
  allow_inscriptions: boolean;
  allow_runes: boolean;
  allow_brc20: boolean;
  // Size limits.
  max_op_return_size: number;   // bytes; 0 = no OP_RETURN allowed
  max_witness_per_input: number; // bytes per input
  max_tx_outputs: number;        // outputs per tx
  max_tx_size: number;           // vbytes per tx
  // Fee floor.
  min_fee_rate: number;          // sat/vB; 0 = no minimum
}

export interface PolicyCustomResult {
  success: boolean;
  profile: 'custom';
  restart_pending: boolean;
}

// Sensible starting values for a fresh custom policy (mirrors the backend
// CustomPolicyConfig defaults: T0+T1+T2, no data, small-OP_RETURN limits).
export const POLICY_CUSTOM_DEFAULTS: PolicyCustomConfig = {
  allow_t0: true,
  allow_t1: true,
  allow_t2: true,
  allow_t3: false,
  allow_inscriptions: false,
  allow_runes: false,
  allow_brc20: false,
  max_op_return_size: 80,
  max_witness_per_input: 400,
  max_tx_outputs: 100,
  max_tx_size: 100_000,
  min_fee_rate: 1.0,
};

export async function setPolicyCustom(config: PolicyCustomConfig): Promise<PolicyCustomResult> {
  return fetchApi<PolicyCustomResult>('/api/v1/config/policy_custom', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

// Payout Address Settings
export async function setGhostPayPayoutAddress(address: string | null): Promise<{ address: string | null }> {
  return fetchApi<{ address: string | null }>('/api/v1/settings/ghostpay_payout_address', {
    method: 'POST',
    body: JSON.stringify({ address }),
  });
}

// Haze configuration (wizard endpoint)
export async function configureHaze(mode: 'standard' | 'hazed' | 'full_archive'): Promise<{ success: boolean; mode: string; message: string }> {
  return fetchApi('/api/v1/haze/configure', {
    method: 'POST',
    body: JSON.stringify({ mode }),
  });
}

// Shroud configuration (wizard endpoint)
export async function configureShroud(config: {
  enabled: boolean;
}): Promise<{ success: boolean; enabled: boolean; restart_required: boolean; message: string }> {
  return fetchApi('/api/v1/shroud/configure', {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

// Node restart (wizard endpoint)
export async function restartNode(): Promise<{ success: boolean; message: string }> {
  return fetchApi('/api/v1/node/restart', {
    method: 'POST',
  });
}

// Ghost Pay mode toggle
export async function setGhostPay(enabled: boolean): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/ghost_pay', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

// Wraith mixing toggle — persists `[ghost_pay] wraith_enabled` to the node
// config. A ghost-pool restart applies the change on a live node.
export async function setWraith(
  enabled: boolean,
): Promise<{ success: boolean; enabled: boolean; persisted: boolean; restart_required: boolean; message: string }> {
  return fetchApi('/api/v1/config/wraith', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

// Mining payout address
export async function setMiningPayoutAddress(address: string): Promise<{ success: boolean; message: string }> {
  return fetchApi('/api/v1/mining/payout_address', {
    method: 'POST',
    body: JSON.stringify({ address }),
  });
}

// Mining pool name (coinbase tag)
export async function setPoolName(name: string | null): Promise<{ success: boolean }> {
  return fetchApi('/api/v1/mining/pool_name', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}

