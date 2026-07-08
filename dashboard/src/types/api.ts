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
  capabilities?: Record<string, unknown>;
  archive_mode?: boolean;
  ghost_pay?: boolean;
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
  private_mining?: boolean;
  reaper?: boolean;
  ghost_pay?: boolean;
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
  ghost_pay?: boolean;
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
}

export interface FullNodeConfig {
  // Backend may return flat or nested structure
  node?: {
    ghost_mode: boolean;
    ghost_mode_local_egress?: boolean;
    archive_mode: boolean;
    public_mining: boolean;
  };
  mining?: {
    private_mining: boolean;
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
  payout?: {
    address: string | null;
    ghostpay_address: string | null;
    min_payout: number;
    auto_payout: boolean;
  };
  // Block-priority lever from pool.toml [pool].block_priority. Governs template
  // ORDERING: `max_fee` (default, revenue) or `payments_first` (seat BUDS
  // financial txs ahead of data txs). Permutation only — weight-safe.
  block_priority?: 'max_fee' | 'payments_first';
  // Flat fields from backend
  ghost_mode?: boolean;
  ghost_mode_local_egress?: boolean;
  archive_mode?: boolean;
  public_mining?: boolean;
  reaper?: boolean;
  ghost_pay?: boolean;
  elder?: boolean;
  [key: string]: unknown;
}

// L2 Pruning config (from /api/v1/ghost-pay/pruning). The backend returns the
// profile-derived enable flag + sat threshold; the *_pruned counters are only
// populated once a prune has run.
export interface L2PruningConfig {
  enabled?: boolean;
  profile?: string;
  threshold_sats?: number;
  last_prune?: number | null;
  retention_days?: number;
  auto_prune?: boolean;
  prune_interval_hours?: number;
  last_prune_timestamp?: number;
  payments_pruned?: number;
  attestations_pruned?: number;
  locks_pruned?: number;
  [key: string]: unknown;
}

// L2 fee-distribution context (from /api/v1/l2/fee-distribution-context) — the
// treasury pool plus the set of Ghost Pay-capable nodes that share L2 fees.
export interface L2FeeDistributionNode {
  node_id: string;
  address: string;
  shares: number;
}

export interface L2FeeDistributionContext {
  treasury_balance_sats?: number;
  threshold_reached_at?: number | null;
  ghost_pay_nodes?: L2FeeDistributionNode[];
  error?: string;
}

// L2 commitment-tree state (from /api/v1/l2/tree-state).
export interface L2TreeState {
  epoch?: number;
  tree_root?: string;
  checkpoint_height?: number;
  checkpoint_root?: string;
  checkpoint_tx_count?: number;
  note_count?: number;
  recent_finalizations?: number;
  active_finalizations?: number;
  roots_match?: boolean;
  error?: string;
}

export interface SharesInfo {
  total: number;
  max_shares: number;
  uptime_percent?: number;
  uptime_qualified?: boolean;
  // 5-4-3-2-1 Share Model
  archive_mode?: boolean;      // +5
  ghost_pay?: boolean;         // +4
  public_mining?: boolean;     // +3
  reaper?: boolean;      // +2
  elder?: boolean;             // +1
  elder_slot?: number | null;
  estimated_reward_btc?: number | null;
}

// VERIFIED node capabilities as reported by /health. Unlike the CLAIMED
// capabilities on /api/v1/node/shares, these reflect what the node has actually
// proved via challenge-response and is therefore paid for (5-4-3-2-1 model).
export interface HealthCapabilities {
  archive_mode?: boolean;   // +5
  ghost_pay?: boolean;      // +4
  public_mining?: boolean;  // +3
  reaper?: boolean;         // +2
  elder_status?: boolean;   // +1
  gsp_enabled?: boolean;
  total_shares?: number;
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
  capabilities?: HealthCapabilities;
}

// WebSocket event types
export type NodeEvent =
  | { type: "StatusChange"; data: NodeStatusSnapshot }
  | { type: "ConfigChange"; data: { key: string; value: string } }
  | { type: "SharesUpdate"; data: SharesInfo }
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
  shares_this_round?: number;
  difficulty?: number;
  best_hash?: string | null;
  // Dashboard-compatible aliases (added to backend)
  enabled?: boolean;
  private_mining?: boolean;
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
  payout_address?: string | null;
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

export interface MinerInfo {
  worker_name?: string;
  hashrate_th?: number;
  shares_submitted?: number;
  shares_accepted?: number;
  last_share?: number;
  connected_at?: number;
  ip_address?: string;
  // Backend fields
  miner_id?: string;
  address?: string;
  difficulty?: number;
  total_shares?: number;
  valid_shares?: number;
  stale_shares?: number;
  last_share_at?: number;
  user_agent?: string;
}

export interface MinersResponse {
  // `/api/v1/mining/miners/full` returns `total`; the operator-authed
  // `/api/v1/mining/miners` returns `total_miners`. Both are optional so the
  // count can be sourced from whichever endpoint answered.
  total?: number;
  total_miners?: number;
  miners?: MinerInfo[];
  // True when the backend withheld the per-miner list (public/unauthed path or
  // a pre-redeploy node that lacks the operator-authed detail mode). When true,
  // `miners` is absent and the UI shows the aggregate count instead of a table.
  miners_redacted?: boolean;
  // Aggregate stats returned when miners array is not available (no HMAC auth)
  total_hashrate_th?: number;
  total_shares_accepted?: number;
  total_shares_submitted?: number;
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

// Mesh-wide leaderboard (GET /api/v1/pool/mesh-leaderboard) — node-ranked
// leaderboard + mesh-wide best-share records per window, aggregated with no new
// gossip.
export interface MeshLeaderboardNode {
  node_id: string;
  name: string;
  hashrate_th: number;
  miner_count: number;
  shares: number;
  elder: boolean;
  healthy: boolean;
  is_self: boolean;
}

export interface MeshLeaderboardRecord {
  window: string;
  share_hash: string;
  leading_zero_bits: number;
  leading_hex_zeros: number;
  miner_id_redacted: string;
  timestamp: number;
  difficulty: number;
}

export interface MeshLeaderboardResponse {
  nodes: MeshLeaderboardNode[];
  node_count: number;
  records: MeshLeaderboardRecord[];
  limit_note: string;
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

// Rewards types
export interface RewardsCurrent {
  // Backend fields
  round_id?: number;
  block_height?: number;
  pending_rewards_sats?: number;
  total_earned_sats?: number;
  last_credited_round?: number;
  estimated_share?: number;
  node_shares?: number;
  total_network_shares?: number;
  // Dashboard-compatible aliases
  estimated_reward_btc?: number;
  current_round_shares?: number;
  pool_hashrate_ph?: number;
  estimated_time_to_payout_hours?: number;
}

export interface PayoutRecord {
  // Backend fields
  round_id?: number;
  amount_sats?: number;
  status?: string;
  created_at?: number;
  // Dashboard fields
  txid?: string;
  amount_btc: number;
  timestamp: number;
  block_height?: number;
  payout_type: string;
}

export interface RewardsHistory {
  // Backend returns
  rewards?: PayoutRecord[];
  total_rewards?: number;
  total_earned_sats?: number;
  // Dashboard aliases
  total_earned_btc?: number;
  payouts?: PayoutRecord[];
}

// Network types
export interface PoolStatus {
  // Backend fields
  pool_name?: string;
  version?: string;
  block_height?: number;
  peer_count?: number;
  miner_count?: number;
  round_id?: number;
  uptime_secs?: number;
  total_shares?: number;
  // Dashboard aliases
  connected?: boolean;
  pool_hashrate_ph?: number;
  active_nodes?: number;
  active_miners?: number;
  blocks_found?: number;
  current_round_duration_secs?: number;
  estimated_time_to_block_secs?: number;
}

export interface PeerInfo {
  node_id?: string;
  address?: string;
  latency_ms?: number;
  synced?: boolean;
  version?: string;
  connected_at?: number;
  last_seen?: number;
  is_self?: boolean;
}

export interface PeersResponse {
  total: number;
  peers: PeerInfo[];
}

export interface TreasuryStatus {
  // Backend fields
  treasury_address?: string;
  treasury_balance_sats?: number;
  fee_percent?: number;
  total_fees_collected?: number;
  total_payouts?: number;
  // Shared fields
  phase?: "bootstrap" | "decay" | "ossified" | string;
  decay_started?: boolean;
  accumulated_btc?: number;
  target_btc?: number;
  progress_percent?: number;
  treasury_percent?: number;
  node_pool_percent?: number;
  // Dashboard aliases
  decay_year?: number | null;
  decay_rate?: number | null;
  blocks_until_full?: number | null;
}

export interface GhostPayStatus {
  enabled?: boolean;
  node_id?: string;
  protocol_version?: number;
  network?: string;
  l2_era?: number;
  virtual_block?: number;
  l2_height?: number;
  block_height?: number;
  epoch?: number;
  peer_count?: number;
  uptime_secs?: number;
  sync_state?: string;
  wraith_enabled?: boolean;
  ghostpay_hosts_mixing?: boolean;
  total_balances?: number;
}

export interface ElderStatus {
  // Backend fields
  elders?: Array<{
    node_id: string;
    display_name: string;
    elder_order: number;
    first_seen: number;
    last_seen: number;
    is_self: boolean;
  }>;
  total_elders?: number;
  max_elders?: number;
  spots_remaining?: number;
  // Shared
  is_elder?: boolean;
  elder_slot?: number | null;
  active_elders?: number;
  registered_at?: number | null;
  downtime_warning?: boolean;
  consecutive_downtime_days?: number;
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

// Wraith types
export type WraithTier = "Test" | "Dev" | "Express" | "Quick" | "Small" | "Medium" | "Standard" | "Large" | "Whale" | string;
export type WraithDenomination = "Tiny" | "Small" | "Medium" | "Large" | string;
export type WraithSessionStatus = "Filling" | "Full" | "Signing" | "Complete" | "Expired" | "Failed" | string;

export interface WraithSession {
  // Backend fields
  round_id?: string;
  denomination?: string;
  amount_sats?: number;
  participant_count?: number;
  phase?: string | number;
  registration_deadline?: number;
  // Dashboard fields
  session_id?: string;
  tier?: WraithTier;
  status?: WraithSessionStatus;
  min_participants?: number;
  your_index?: number | null;
  fill_percentage?: number;
  expires_at?: number;
  action_required?: string | null;
}

export interface WraithStats {
  total_sessions?: number;
  active_sessions?: number;
  sessions_completed?: number;
  sessions_expired?: number;
  total_participants?: number;
  avg_fill_rate?: number;
  your_participations?: number;
  your_completed?: number;
}

export interface WraithSessionsResponse {
  sessions: WraithSession[];
  // Backend puts stats at top level
  total?: number;
  active?: number;
  active_sessions?: number;
  sessions_completed?: number;
  total_sessions?: number;
  sessions_expired?: number;
  total_participants?: number;
  // Dashboard expects nested stats
  stats?: WraithStats;
}

// Ghost Lock types
export type LockDenomination = "Micro" | "Tiny" | "Small" | "Medium" | "Large" | string;
export type TimelockTier = "Short" | "Standard" | "Long" | string;
export type LockStatus = "Active" | "PendingSettlement" | "InMixing" | "Settled" | "Expired" | string;

export interface GhostLock {
  lock_id: string;
  denomination: string;
  balance: number;
  amount_sats?: number;
  nonce: number;
  status: string;
  state?: string;
  utxo_txid?: string | null;
  utxo_vout?: number | null;
  utxo_confirmed?: boolean;
  timelock_tier: string;
  expires_at: number | null;
  batch_id?: string | null;
  batch_signatures?: string | null;
  // Backend fields
  creation_height?: number;
  recovery_height?: number;
  funding_txid?: string | null;
  next_jump_height?: number | null;
  created_at?: number;
}

export interface GhostLockSummary {
  total_locks?: number;
  total_balance?: number;
  available_balance?: number;
  pending_settlement?: number;
  in_mixing?: number;
}

export interface GhostLocksResponse {
  locks: GhostLock[];
  // Backend fields
  enabled?: boolean;
  active_locks?: number;
  total_locked_sats?: number;
  // Dashboard alias
  summary?: GhostLockSummary;
}

// Payment types
export type PaymentType = "IN" | "OUT" | string;
export type PaymentStatus = "Pending" | "Confirmed" | "Failed" | string;

export interface Payment {
  // Backend fields
  id?: string;
  round_id?: number;
  recipient?: string;
  recipient_type?: string;
  amount_sats?: number;
  address?: string | null;
  txid?: string | null;
  type: string;
  created_at?: number;
  // Dashboard fields
  payment_id: string;
  lock_id?: string;
  counterparty_id: string;
  amount: number | null;
  status?: string;
  block_height?: number | null;
  timestamp: number;
}

export interface PaymentsResponse {
  payments: Payment[];
  total: number;
  pending_count: number;
}

// Settlement types
export type SettlementClass = "Express" | "Standard" | "Economy" | string;
export type BatchStatus = "Forming" | "CollectingSignatures" | "Ready" | "Broadcast" | "Confirmed" | "Failed" | string;

// Live `/settlement/status` response — a flat object (no nested `stats`/`batches`).
export interface SettlementResponse {
  status?: string;
  pending_settlements?: number;
  pending_count?: number;
  batches_24h?: number;
  last_settlement?: Record<string, unknown> | null;
  total_settled_sats?: number;
}

// Node-level settlement service status, derived from the flat SettlementResponse.
export interface SettlementStatus {
  status?: string;
  pending_count?: number;
  batches_24h?: number;
  total_settled_sats?: number;
}

// Jump Queue types
export interface JumpQueueStats {
  pending_count?: number;
  processing_count?: number;
  total_enqueued?: number;
  total_completed?: number;
  total_failed?: number;
  avg_wait_time_secs?: number;
  total_volume_sats?: number;
  liquidity_available_sats?: number;
}

// Ghost Pay events/alerts
export type GhostPayEventSeverity = "info" | "warning" | "error";

export interface GhostPayEvent {
  id?: string;
  severity?: GhostPayEventSeverity;
  category?: string;
  message?: string;
  timestamp?: string;
  details?: Record<string, unknown>;
}

// L2 Mempool types
export interface L2MempoolStats {
  pending_count?: number;
  pending_volume_sats?: number;
  avg_payment_size_sats?: number;
  throughput_per_min?: number;
  avg_wait_secs?: number;
  avg_fee_sats?: number;
  total_fees_24h?: number;
}

export type SizeTier = "micro" | "tiny" | "small" | "medium" | "large" | "xl";

export interface MempoolTransaction {
  tx_id?: string;
  size_tier?: SizeTier;
  fee_sats?: number;
  age_secs?: number;
}

export interface BlockLeader {
  height?: number;
  leader_node_id?: string;
  tx_count?: number;
  timestamp?: number;
}

// WebSocket mempool events
export type MempoolEvent =
  | { type: "mempool_snapshot"; transactions: MempoolTransaction[]; stats: L2MempoolStats }
  | { type: "tx_added"; transaction: MempoolTransaction }
  | { type: "tx_removed"; tx_id: string }
  | { type: "block_confirmed"; block: BlockLeader }
  | { type: "stats_update"; stats: L2MempoolStats };

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
  // Capability fields
  shares?: number;
  max_shares?: number;
  uptime_percent?: number;
  peer_count?: number;
  balance_btc?: number;
  l1_height?: number;
  l2_height?: number;
  miner_count?: number;
  archive_mode?: boolean;
  ghost_pay?: boolean;
  public_mining?: boolean;
  reaper?: boolean;
  elder?: boolean;
  elder_slot?: number | null;
  hashrate_th?: number;
  watchdog_health?: string;
  watchdog_errors?: number;
  capabilities?: Record<string, unknown>;
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
  combined_shares?: number;
  max_combined_shares?: number;
  total_balance_btc?: number;
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

// Enhanced Rewards types
export interface EarningsSummary {
  total_earned_all_time?: number;
  pending_btc?: number;
  earned_this_month?: number;
  earned_this_week?: number;
  earned_today?: number;
  daily_average?: number;
}

export interface EarningsProjection {
  daily?: number;
  weekly?: number;
  monthly?: number;
  yearly?: number;
  daily_with_all_shares?: number;
  potential_increase_percent?: number;
}

export interface ShareContribution {
  tier?: string;
  bonus?: number;
  enabled?: boolean;
  contribution_percent?: number | null;
}

export interface RewardsFullResponse {
  // Backend fields
  round_id?: number;
  block_height?: number;
  node_shares?: number;
  total_network_shares?: number;
  estimated_reward_sats?: number;
  lifetime_rewards_sats?: number;
  pending_rewards_sats?: number;
  total_withdrawals_sats?: number;
  last_credited_round?: number;
  last_payout?: Record<string, unknown> | null;
  rewards_history?: PayoutRecord[];
  capabilities?: Record<string, boolean>;
  // Dashboard aliases
  summary?: EarningsSummary;
  shares?: SharesInfo;
  share_contributions?: ShareContribution[];
  network_total_shares?: number;
  your_share_of_pool_percent?: number;
  projections?: EarningsProjection;
  payouts?: PayoutRecord[];
  daily_earnings?: DailyEarning[];
}

export interface DailyEarning {
  date: string;
  amount_btc: number;
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

// ============================================================================
// Payout History Types (for transparency)
// ============================================================================

export type PayoutHistoryTimeFilter = "24h" | "7d" | "all";

export interface NetworkPayoutEntry {
  // Backend fields
  round_id?: number;
  recipient_id?: string;
  recipient_type?: string;
  amount_sats?: number;
  address?: string | null;
  txid?: string | null;
  status?: string;
  created_at?: number;
  // Dashboard fields
  block_height?: number;
  block_hash?: string | null;
  timestamp?: number;
  entry_type?: string;
  amount_satoshis?: number;
  recipient_address?: string | null;
  recipient_node_id?: string | null;
}

export interface NetworkPayoutSummary {
  total_treasury_satoshis: number;
  total_node_rewards_satoshis: number;
  total_miner_rewards_satoshis: number;
  blocks_in_period: number;
}

export interface NetworkPayoutHistoryResponse {
  // Backend returns
  payouts?: NetworkPayoutEntry[];
  total?: number;
  // Dashboard aliases
  entries?: NetworkPayoutEntry[];
  summary?: NetworkPayoutSummary;
}

export interface GhostPayFeeEntry {
  block_height?: number;
  batch_id?: string;
  fee_satoshis?: number;
  timestamp?: number;
  recipient_node_id?: string | null;
}

export interface WraithFeeEntry {
  block_height?: number;
  session_id?: string;
  fee_satoshis?: number;
  timestamp?: number;
  recipient_node_id?: string | null;
}

export interface GhostPayPayoutSummary {
  total_ghostpay_fees_satoshis: number;
  total_wraith_fees_satoshis: number;
  ghostpay_sessions_count: number;
  wraith_sessions_count: number;
}

export interface GhostPayPayoutHistoryResponse {
  // Backend returns
  payouts?: Record<string, unknown>[];
  total?: number;
  // Dashboard aliases
  ghostpay_fees?: GhostPayFeeEntry[];
  wraith_fees?: WraithFeeEntry[];
  summary?: GhostPayPayoutSummary;
}

export interface NodePayoutEntry {
  // Backend fields
  node_id?: string;
  balance_sats?: number;
  last_credited_round?: number;
  total_credits_sats?: number;
  total_withdrawals_sats?: number;
  is_self?: boolean;
  created_at?: number;
  updated_at?: number;
  // Dashboard fields
  block_height?: number;
  block_hash?: string | null;
  timestamp?: number;
  payout_type?: string;
  amount_satoshis?: number;
  share_count?: number | null;
  share_percentage?: number | null;
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
  error?: string;
}

// Ghost Shroud — relay privacy configuration
export interface ShroudStatus {
  enabled: boolean;
  ghost_core_connected: boolean;
  max_delay_ms: number;
  avg_delay_ms: number;
}

// Tor mode status from gettormode RPC
export interface TorModeStatus {
  enabled: boolean;
  onion_address?: string;
  embedded_tor: boolean;
  tor_pid?: number;
  tor_running?: boolean;
}
