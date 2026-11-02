// Ghost Node API Types
// Types match the actual backend response shapes from routes.rs

export interface NodeInfo {
  node_id: string;
  node_id_short: string;
  nickname?: string;
  version: string;
  uptime_seconds?: number;
  uptime_secs?: number;
  sync_height?: number;
  block_height?: number;
  round_id?: number;
  network?: string;
  is_synced?: boolean;
  peer_count?: number;
  miner_count?: number;
  archive_mode?: boolean;
  public_mining?: boolean;
  reaper?: boolean;
  mempool_profile?: string;
  template_profile?: string;
}

export interface NodeStatus {
  online?: boolean;
  node_id?: string;
  version?: string;
  sync_height?: number;
  block_height?: number;
  round_id?: number;
  is_synced?: boolean;
  peer_count?: number;
  miner_count?: number;
  uptime_seconds?: number;
  uptime_secs?: number;
  ghost_mode?: boolean;
  ghost_mode_local_egress?: boolean;
  tor_mode?: boolean;
  onion_address?: string;
  archive_mode?: boolean;
  public_mining?: boolean;
  reaper?: boolean;
}

// Chain & sync status, sourced from ghostd `getblockchaininfo`
// (/api/v1/node/blockchain). Numeric fields are null when the RPC is
// unavailable (available === false), so the UI degrades to "—".
export interface BlockchainStatus {
  available: boolean;
  network?: string | null;
  chain?: string | null;
  blocks?: number | null;
  headers?: number | null;
  best_block_hash?: string | null;
  difficulty?: number | null;
  size_on_disk?: number | null;
  verification_progress?: number | null;
  initial_block_download?: boolean | null;
  pruned?: boolean | null;
  hazed?: boolean | null;
  median_time?: number | null;
  tip_time?: number | null;
  chainwork?: string | null;
  warnings?: string[] | null;
}

export interface NodeConfig {
  ghost_mode?: boolean;
  ghost_mode_local_egress?: boolean;
  archive_mode?: boolean;
  reaper?: boolean;
  public_mining?: boolean;
}

// Pruning configuration — the VW/OW/AW three-window model. Pruning is
// block-storage only and is deliberately NOT tied to BUDS tx-filtering.
export interface PruningConfig {
  // Validator Window: the mandatory Bitcoin Core prune floor (read-only).
  vw_blocks?: number;
  // Operator Window: the one editable depth knob = storage.prune_height
  // (blocks to keep, 0 = keep everything short of the Archive Window).
  ow_blocks?: number;
  // Archive Window: storage.archive_mode (when true, pruning is disabled).
  archive_mode?: boolean;
  // A one-time pruned→archive reindex/resync is still in flight (ghostd is
  // rebuilding and re-downloading the full chain). Cleared automatically once
  // the resync completes.
  reindex_pending?: boolean;
}

export interface FullNodeConfig {
  // Backend may return flat or nested structure
  node?: {
    ghost_mode: boolean;
    ghost_mode_local_egress?: boolean;
    archive_mode: boolean;
  };
  mining?: {
    stratum_v1_port: number;
    stratum_v2_port: number;
    max_miners: number;
    min_difficulty: number;
    vardiff_enabled: boolean;
  };
  pruning?: PruningConfig;
  // The real tier policy from pool.toml [policy]. `profile` is the lever that
  // decides which BUDS tiers get mined (strict / permissive / full_open / custom).
  // `custom` carries the resolved per-field values for the advanced panel.
  policy?: {
    profile?: string;
    /** What ghostd is ACTUALLY enforcing (parsed from its systemd ExecStart),
     * vs `profile` which is only what pool.toml intends. */
    enforced_profile?: string;
    /** True when enforced_profile disagrees with the configured profile. */
    drift?: boolean;
    custom?: {
      allow_t0: boolean;
      allow_t1: boolean;
      allow_t2: boolean;
      allow_t3: boolean;
      allow_inscriptions: boolean;
      allow_runes: boolean;
      allow_brc20: boolean;
      max_op_return_size: number;
      max_witness_per_input: number;
      max_tx_outputs: number;
      max_tx_size: number;
      min_fee_rate: number;
    };
  };
  // Block-priority lever from pool.toml [pool].block_priority. Governs template
  // ORDERING: `max_fee` (default, revenue) or `payments_first` (seat BUDS
  // financial txs ahead of data txs). Permutation only — weight-safe.
  block_priority?: 'max_fee' | 'payments_first';
  // Block-template refresh cadence in seconds (pool.toml [pool].template_refresh_secs),
  // clamped [10, 60]. How often the template is rebuilt for fresh mempool fees.
  template_refresh_secs?: number;
  // Flat fields from backend
  ghost_mode?: boolean;
  ghost_mode_local_egress?: boolean;
  archive_mode?: boolean;
  reaper?: boolean;
  [key: string]: unknown;
}

export interface HealthStatus {
  status?: string;
  healthy?: boolean;
  uptime_seconds?: number;
  uptime_secs?: number;
  block_height?: number;
  peer_count?: number;
  miner_count?: number;
  round_id?: number;
  node_id?: string;
  version?: string;
}

// WebSocket event types
export type NodeEvent =
  | { type: "StatusChange"; data: NodeStatusSnapshot }
  | { type: "ConfigChange"; data: { key: string; value: string } }
  | { type: "HealthChange"; data: { healthy: boolean; message: string } };

export interface NodeStatusSnapshot {
  sync_height?: number;
  block_height?: number;
  is_synced?: boolean;
  peer_count?: number;
  uptime_seconds?: number;
  uptime_secs?: number;
  ghost_mode?: boolean;
  ghost_mode_local_egress?: boolean;
  archive_mode?: boolean;
}

// Mining types
export interface MiningStatus {
  // Backend fields
  active?: boolean;
  miner_count?: number;
  total_hashrate?: number;
  difficulty?: number;
  best_hash?: string | null;
  // Dashboard-compatible aliases (added to backend)
  enabled?: boolean;
  public_mining?: boolean;
  hashrate_th?: number;
  local_hashrate_th?: number;
  local_connected_miners?: number;
  active_miners?: number;
  mesh_active_miners?: number;
  connected_miners?: number;
  shares_submitted?: number;
  shares_accepted?: number;
  shares_rejected?: number;
  stratum_v1_port?: number;
  stratum_v2_port?: number;
  stratum_v1_endpoint?: string;
  stratum_v2_endpoint?: string;
  pool_name?: string | null;
  block_height?: number;
  sync_height?: number;
  round_id?: number;
  blocks_found?: number;
  is_synced?: boolean;
  // SV2/Noise authority public key that miners must pin. Sourced from the
  // node's `[network] sv2_authority_public_key`, falling back to the
  // network-wide default. Optional: absent on pre-redeploy nodes, in which
  // case the frontend falls back to its bundled constant.
  authority_public_key?: string;
}

// Pool time-series (GET /api/v1/pool/series) — rolling server-side history of
// pool hashrate + connected miners, sampled every 30s (24h retention).
export interface PoolSeriesSample {
  /** Unix timestamp (seconds). */
  t: number;
  /** Mesh-wide pool hashrate (TH/s). */
  mesh_hashrate_th: number;
  /** This node's own realized hashrate (TH/s). */
  local_hashrate_th: number;
  /** Mesh-wide deduplicated connected-miner count. */
  miners: number;
  /** Transactions in this node's mempool at sample time (getmempoolinfo.size).
   *  Optional: absent on nodes whose `/pool/series` ring predates this field. */
  mempool_txs?: number;
  /** Transactions in the block template this node was building at sample time.
   *  Optional: absent on nodes whose `/pool/series` ring predates this field. */
  block_txs?: number;
}

export interface PoolSeriesResponse {
  window: string;
  window_secs: number;
  sample_interval_secs: number;
  count: number;
  samples: PoolSeriesSample[];
}

// Chain health (GET /api/v1/chain/health) — the current tip-lag status plus
// recently recorded reorg events. Persisted server-side in a bounded ring, so
// operators can SEE reorgs and tip-lag (both historically only fired alerts).

/** Derived tip-lag status label. `at_tip` is the normal, healthy state. */
export type TipStatusKind = "at_tip" | "behind" | "stale";

export interface ChainTipStatus {
  /** This node's current local L1 height. */
  local_height: number;
  /** Highest L1 height reported by a fresh connected mesh peer (0 = unknown). */
  best_peer_height: number;
  /** How many blocks behind the best peer (0 when caught up or peer unknown). */
  behind_by: number;
  /** Seconds since the local height last advanced (tip age). */
  tip_age_secs: number;
  /** Derived status label. */
  status: TipStatusKind;
}

export interface ChainReorgEvent {
  /** Unix timestamp (seconds) the reorg was recorded. */
  unix_time: number;
  /** Consecutive-disconnect depth when this block was orphaned. */
  depth: number;
  /** Hash of the disconnected (orphaned) block — the old tip. */
  old_tip_hash: string;
  /** Local height right after the disconnect, when a height source is wired. */
  new_tip_height?: number;
}

export interface ChainHealthResponse {
  /** Latest tip-status snapshot; null until the monitor has run once. */
  tip: ChainTipStatus | null;
  /** Recently recorded reorg events, newest first. */
  reorgs: ChainReorgEvent[];
  /** Reorgs recorded in the last 24h; 0 is the normal, healthy state. */
  reorg_count_24h: number;
}

// Best Hash types
export interface BestHashEntry {
  hash?: string | null;
  difficulty?: number;
  timestamp?: number;
  miner_id?: string | null;
  block_height?: number;
}

export interface BestHashResponse {
  current_round?: BestHashEntry;
  last_round?: BestHashEntry;
  last_hour?: BestHashEntry;
  last_24h?: BestHashEntry;
  all_time?: BestHashEntry;
  // Raw backend fields
  best_hash?: string | null;
  best_difficulty?: number;
  network_hashrate?: number;
  block_height?: number;
  round_id?: number;
  chain?: string;
}

// Logs types
export interface LogEntry {
  timestamp: number;
  level: "trace" | "debug" | "info" | "warn" | "error";
  target: string;
  message: string;
  // journalctl fields
  unit?: string;
  priority?: string;
}

export interface LogsResponse {
  entries: LogEntry[];
  // Present on multi-binary responses; absent on legacy ring-buffer-only shape.
  unit?: string;
  source?: "ring-buffer" | "journald";
  // Honest structured error (e.g. journald permission denied); null on success.
  error?: string | null;
}

// A selectable log source (binary) reported by /api/v1/logs/units.
export interface LogUnit {
  key: string;
  label: string;
  description: string;
  source: "ring-buffer" | "journald";
  available: boolean;
}

export interface LogUnitsResponse {
  units: LogUnit[];
  default: string;
}

// Swarm types
export interface SwarmNode {
  node_id: string;
  name?: string;
  address?: string;
  online?: boolean;
  is_self?: boolean;
  version?: string;
  last_seen?: number;
  // Origin of this entry: "mesh" = auto-discovered consensus peer whose status
  // comes from health-ping gossip (never poll-able from here, so never shown
  // "offline" merely because its dashboard API is unreachable); "manual" (or
  // undefined) = an operator-added node polled via its own dashboard API.
  source?: "mesh" | "manual";
  uptime_percent?: number;
  peer_count?: number;
  l1_height?: number;
  miner_count?: number;
  hashrate_th?: number;
  watchdog_health?: string;
  watchdog_errors?: number;
}

export interface SwarmAlert {
  id?: string;
  severity?: "info" | "warning" | "error";
  node_id?: string | null;
  message?: string;
  timestamp?: number;
}

export interface SwarmStats {
  total_nodes?: number;
  online_nodes?: number;
  offline_nodes?: number;
  avg_uptime_percent?: number;
  combined_hashrate_th?: number;
}

export interface SwarmResponse {
  // Backend fields
  enabled?: boolean;
  node_id?: string;
  self?: SwarmNode;
  total?: number;
  // Shared
  nodes: SwarmNode[];
  // Dashboard aliases
  stats?: SwarmStats;
  alerts?: SwarmAlert[];
}

// Backup/Migration types

// Real verification detail returned by the node's /api/v1/backup/verify. These
// come straight from opening the artifact read-only and running an integrity +
// Ghost-schema check — no fabricated fields.
export interface BackupInfo {
  integrity_ok?: boolean;
  encrypted?: boolean;
  schema_version?: number;
  table_count?: number;
  miner_count?: number;
  missing_tables?: string[];
  size_bytes?: number;
  checksum_valid?: boolean;
}

export interface BackupHistoryEntry {
  filename: string;
  type?: "full" | "partial" | string;
  size_bytes?: number;
  created_at?: number;
  exported?: boolean;
}

export interface BackupResponse {
  success: boolean;
  filename: string;
  size_bytes?: number;
  created_at?: number;
  download_url?: string;
  message?: string;
}

export interface VerifyBackupResponse {
  valid?: boolean;
  info?: BackupInfo | null;
  error?: string | null;
}

export interface ImportBackupResponse {
  success: boolean;
  restart_required?: boolean;
  staged_path?: string;
  message?: string;
  error?: string;
}

export interface BackupHistoryResponse {
  backups: BackupHistoryEntry[];
  total?: number;
  backup_dir?: string;
}

// Watchdog types (defined here instead of re-exporting)
export interface ComponentHealth {
  name: string;
  port?: number;
  status: 'ok' | 'error' | 'unknown' | string;
  pid?: number;
  process_name?: string;
  last_check?: number;
}

export interface WatchdogServiceStatus {
  name: string;
  status: 'running' | 'stopped' | 'syncing' | 'error' | 'not_enabled' | 'unknown' | string;
  details?: Record<string, unknown>;
}

export interface WatchdogEvent {
  timestamp?: number;
  event_type?: 'restart' | 'failure' | 'recovery' | 'warning' | string;
  service?: string;
  message?: string;
}

export interface WatchdogStatus {
  components?: ComponentHealth[];
  services?: WatchdogServiceStatus[];
  last_check?: number;
  overall_health?: 'healthy' | 'degraded' | 'unhealthy' | string;
  healthy?: boolean;
  uptime_secs?: number;
}

// Ghost Haze — storage privacy status from Ghost Core
export interface HazeStatus {
  hazed: boolean;
  archive_mode: boolean;
  mode: 'hazed' | 'full_archive' | 'standard' | 'unknown';
  blocks: number;
  size_on_disk: number;
  pruned: boolean;
  chain: string;
  // Exorcism storage metrics (from ghostd `gethazestatus`)
  exorcism_active: boolean;
  /** Total blocks processed through Exorcism. */
  blocks_stripped: number;
  /** Total bytes of arbitrary content kept off disk — the headline savings. */
  bytes_stripped: number;
  /** Chain tip height, used to estimate a full-archive baseline. */
  chain_tip: number;
  /** Size of the structural (`.gsb`) archive actually on disk, in GB. */
  structural_archive_size_gb: number;
  error?: string;
}

// Ghost Haze — Legal Compliance Packet (court-ready proof of non-persistence).
// Proxied from ghostd `getlegalpacket`. On non-hazed nodes the RPC is
// unavailable, so the backend returns `{ available: false, reason }` instead.
export interface LegalPacket {
  /** True when the packet was generated (node is in Hazed mode). */
  available: boolean;
  /** Human-readable reason when `available` is false. */
  reason?: string;
  ghost_core_version?: string;
  specification_version?: string;
  node_mode?: string;
  exorcism_active?: boolean;
  haze_status?: string;
  blocks_stripped?: number;
  chain_tip?: number;
  structural_archive_size_gb?: number;
  hazeable_content_on_disk?: boolean;
  checkpoint_height?: number;
  checkpoint_hash?: string;
  conversion_method?: string;
  conversion_date?: string;
  legal_summary?: string;
  generated_at?: string;
}

// Ghost Haze — signed-checkpoint status (trust anchor), from ghostd
// `getcheckpointstatus`.
export interface CheckpointStatus {
  serving: boolean;
  downloading: boolean;
  /** False when the RPC could not be reached. */
  available?: boolean;
  reason?: string;
  height?: number;
  block_hash?: string;
  utxo_count?: number;
  total_chunks?: number;
  signed?: boolean;
  checkpoint_dir?: string;
  chunks_received?: number;
  chunks_total?: number;
  percent_complete?: number;
}

// Ghost Shroud — relay privacy configuration
export interface ShroudStatus {
  enabled: boolean;
  ghost_core_connected: boolean;
  max_delay_ms: number;
  avg_delay_ms: number;
}

// Filtering activity (GET /api/v1/filtering/activity) — per-stage counts of the
// transactions this node has rejected since it started. Two stages: Stage 1 is
// the mempool (Reaper spam-strip + the tier/BUDS policy), Stage 2 is the block
// template (the Reaper strips dead weight when the block is built). All counts
// are cumulative since node start. The endpoint may 404 during rollout, so the
// hook degrades to null and the UI shows a "no rejections yet" state.
export interface FilteringStageCount {
  /** Transactions rejected by this filter at this stage. */
  txs: number;
  /** Virtual bytes those rejected transactions accounted for. */
  vbytes: number;
}

export interface FilteringActivity {
  // Stage 1 — your mempool: never kept, relayed, or mined.
  stage1_mempool: {
    reaper: FilteringStageCount;
    tier: FilteringStageCount;
  };
  // Stage 2 — your block: stripped when the block template is built.
  stage2_block: {
    reaper: FilteringStageCount;
  };
  totals: {
    rejected_txs: number;
  };
}

// Tor mode status from gettormode RPC
export interface TorModeStatus {
  enabled: boolean;
  onion_address?: string;
  embedded_tor: boolean;
  tor_pid?: number;
  tor_running?: boolean;
}

// The coinbase split of the block currently being built (GET /api/v1/mining/coinbase).
export interface MiningCoinbaseResponse {
  available: boolean;
  height?: number;
  subsidy_sat?: number;
  /** The treasury's fixed base share, S/200; any change Rm cannot pay comes on top. */
  treasury_base_sat?: number;
  /** Rm: what the block pays to miners' balances at most. */
  miner_pool_sat?: number;
  tx_fees_to_finder_sat?: number;
  total_coinbase_sat?: number;
}
