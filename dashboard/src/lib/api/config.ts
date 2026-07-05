// Config API endpoints
import { fetchApi } from './client';
import type { NodeConfig, FullNodeConfig, MempoolProfile, TemplateProfile, PruneProfile, L2PruningConfig } from '@/types/api';

export async function getConfig(): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config');
}

export async function getFullConfig(): Promise<FullNodeConfig> {
  return fetchApi<FullNodeConfig>('/api/v1/config/full');
}

// Pruning configuration
export async function setPruneProfile(profile: PruneProfile): Promise<FullNodeConfig> {
  return fetchApi<FullNodeConfig>('/api/v1/config/prune_profile', {
    method: 'POST',
    body: JSON.stringify({ profile }),
  });
}

export async function setOperatorWindow(blocks: number): Promise<FullNodeConfig> {
  return fetchApi<FullNodeConfig>('/api/v1/config/operator_window', {
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

export async function setMempoolProfile(profile: MempoolProfile): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/mempool_profile', {
    method: 'POST',
    body: JSON.stringify({ profile }),
  });
}

export async function setTemplateProfile(profile: TemplateProfile): Promise<NodeConfig> {
  return fetchApi<NodeConfig>('/api/v1/config/template_profile', {
    method: 'POST',
    body: JSON.stringify({ profile }),
  });
}

// The REAL tier policy (pool.toml [policy].profile). Unlike mempool/template
// profile, this actually governs which BUDS tiers get mined. Writing it persists
// to pool.toml and triggers a graceful restart to apply.
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

// Custom profiles (new)
// Mempool Policy Profile - Bitcoin Core options + Ghost extensions + BUDS tiers
export interface CustomMempoolProfile {
  name: string;
  // Core mempool settings
  min_relay_tx_fee: number;           // sat/vB - minimum fee to relay
  max_mempool_size: number;           // MB - max mempool size
  mempool_expiry: number;             // hours - tx expiration time
  max_orphan_tx: number;              // max orphan transactions
  // Transaction acceptance options
  permit_bare_multisig: boolean;      // allow bare multisig (no p2sh wrapper)
  datacarrier: boolean;               // allow OP_RETURN transactions
  datacarrier_size: number;           // max OP_RETURN size in bytes
  accept_non_std_outputs: boolean;    // accept non-standard outputs
  // RBF settings
  mempool_full_rbf: boolean;          // allow full RBF
  incremental_relay_fee: number;      // sat/vB - min fee increase for RBF

  // === Ghost Extensions (Custom Options) ===
  // Spam/Dust Protection
  dust_limit: number;                 // sat - minimum output value
  max_tx_size: number;                // vB - reject txs larger than this
  // Output type preferences
  prefer_native_segwit: boolean;      // prioritize bc1q/bc1p outputs
  reject_legacy_p2pkh: boolean;       // reject P2PKH outputs entirely
  // Inscription/Ordinal filtering
  filter_inscriptions: boolean;       // reject Ordinal inscriptions
  filter_brc20: boolean;              // reject BRC-20 token transfers
  filter_runes: boolean;              // reject Rune transfers
  max_witness_size: number;           // bytes - limit witness data (inscription blocker)
  // Lightning-friendly options
  prioritize_ln_opens: boolean;       // boost Lightning channel opens
  prioritize_ln_closes: boolean;      // boost cooperative channel closes
  // Privacy preferences
  prefer_coinjoin: boolean;           // boost CoinJoin transactions
  min_coinjoin_participants: number;  // minimum participants for CoinJoin boost
  // Chain limits (ancestor/descendant)
  max_ancestor_count: number;         // max unconfirmed ancestors
  max_descendant_count: number;       // max unconfirmed descendants
  max_ancestor_size: number;          // vB - max combined ancestor size

  // BUDS tiers (requires BUDS activation)
  accept_t0: boolean;                 // Standard Bitcoin txs
  accept_t1: boolean;                 // Privacy-enhanced txs
  accept_t2: boolean;                 // Complex/smart contract txs
  accept_t3: boolean;                 // Experimental txs
}

// Block Template Profile - Bitcoin Core options + Ghost extensions + BUDS tiers
export interface CustomTemplateProfile {
  name: string;
  // Core template settings
  block_max_weight: number;           // max block weight (default 4M)
  block_min_tx_fee: number;           // sat/vB - min fee for inclusion
  // Priority settings
  prioritise_by_fee: boolean;         // prioritise by fee rate
  prioritise_by_age: boolean;         // factor in tx age

  // === Ghost Extensions (Custom Options) ===
  // Block composition preferences
  reserve_weight_for_ln: number;      // WU - reserve space for Lightning txs
  max_sigops_per_block: number;       // limit sigops (spam protection)
  prefer_small_txs: boolean;          // include more small txs vs fewer large
  // Inscription/Ordinal filtering
  filter_inscriptions: boolean;       // exclude Ordinal inscriptions from blocks
  filter_brc20: boolean;              // exclude BRC-20 transfers
  filter_runes: boolean;              // exclude Rune transfers
  max_witness_item: number;           // bytes - max single witness item
  // Transaction type preferences
  boost_consolidations: boolean;      // boost UTXO consolidation txs
  boost_batched_payments: boolean;    // boost batched payment txs
  // Package relay / CPFP
  enable_package_relay: boolean;      // enable package-aware selection
  max_package_count: number;          // max txs in a package
  // MEV protection (for L2)
  randomize_tx_order: boolean;        // randomize within fee bands
  fee_band_size: number;              // sat/vB - size of fee bands for randomization
  // Economic preferences
  include_free_relay: boolean;        // include some 0-fee txs (altruistic)
  free_relay_limit: number;           // WU - max space for free txs

  // BUDS tiers (requires BUDS activation)
  include_t0: boolean;                // Standard Bitcoin txs
  include_t1: boolean;                // Privacy-enhanced txs
  include_t2: boolean;                // Complex/smart contract txs
  include_t3: boolean;                // Experimental txs
  // Priority ordering when multiple tiers enabled
  priority_order: string[];           // e.g., ["t0", "t1", "t2", "t3"]
}

export async function getMempoolProfiles(): Promise<{ profiles: CustomMempoolProfile[] }> {
  return fetchApi<{ profiles: CustomMempoolProfile[] }>('/api/v1/config/profiles/mempool');
}

export async function saveMempoolProfile(profile: CustomMempoolProfile): Promise<CustomMempoolProfile> {
  return fetchApi<CustomMempoolProfile>('/api/v1/config/profiles/mempool', {
    method: 'POST',
    body: JSON.stringify(profile),
  });
}

export async function deleteMempoolProfile(name: string): Promise<void> {
  return fetchApi<void>(`/api/v1/config/profiles/mempool/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  });
}

export async function activateMempoolProfile(name: string): Promise<NodeConfig> {
  return fetchApi<NodeConfig>(`/api/v1/config/profiles/mempool/${encodeURIComponent(name)}/activate`, {
    method: 'POST',
  });
}

export async function getTemplateProfiles(): Promise<{ profiles: CustomTemplateProfile[] }> {
  return fetchApi<{ profiles: CustomTemplateProfile[] }>('/api/v1/config/profiles/template');
}

export async function saveTemplateProfile(profile: CustomTemplateProfile): Promise<CustomTemplateProfile> {
  return fetchApi<CustomTemplateProfile>('/api/v1/config/profiles/template', {
    method: 'POST',
    body: JSON.stringify(profile),
  });
}

export async function deleteTemplateProfile(name: string): Promise<void> {
  return fetchApi<void>(`/api/v1/config/profiles/template/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  });
}

export async function activateTemplateProfile(name: string): Promise<NodeConfig> {
  return fetchApi<NodeConfig>(`/api/v1/config/profiles/template/${encodeURIComponent(name)}/activate`, {
    method: 'POST',
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

