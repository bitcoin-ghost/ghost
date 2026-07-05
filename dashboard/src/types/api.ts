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
  tor_mode?: boolean;
  onion_address?: string;
  archive_mode?: boolean;
  public_mining?: boolean;
  private_mining?: boolean;
  reaper?: boolean;
  ghost_pay?: boolean;
  mempool_profile?: MempoolProfile | string;
  template_profile?: TemplateProfile | string;
}

export interface NodeConfig {
  ghost_mode?: boolean;
  archive_mode?: boolean;
  reaper?: boolean;
  public_mining?: boolean;
  ghost_pay?: boolean;
  mempool_profile?: MempoolProfile | string;
  template_profile?: TemplateProfile | string;
}

// Pruning configuration
export type PruneProfile = "default" | "strict" | "clean" | "structured" | "archive";

export interface PruningConfig {
  vw_blocks?: number;
  ow_blocks?: number;
  prune_profile?: PruneProfile | string;
}

export interface FullNodeConfig {
  // Backend may return flat or nested structure
  node?: {
    ghost_mode: boolean;
    archive_mode: boolean;
    public_mining: boolean;
    mempool_profile: string;
    template_profile: string;
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
  // decides which BUDS tiers get mined (strict / permissive / full_open).
  policy?: {
    profile?: string;
  };
  payout?: {
    address: string | null;
    ghostpay_address: string | null;
    min_payout: number;
    auto_payout: boolean;
  };
  // Flat fields from backend
  ghost_mode?: boolean;
  archive_mode?: boolean;
  public_mining?: boolean;
  reaper?: boolean;
  ghost_pay?: boolean;
  mempool_profile?: string;
  template_profile?: string;
  elder?: boolean;
  [key: string]: unknown;
}

// L2 Pruning config (from ghost-pay-node)
export interface L2PruningConfig {
  retention_days?: number;
  auto_prune?: boolean;
  prune_interval_hours?: number;
  last_prune_timestamp?: number;
  payments_pruned?: number;
  attestations_pruned?: number;
  locks_pruned?: number;
  [key: string]: unknown;
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

export type MempoolProfile =
  | "standard"
  | "strict"
  | "clean"
  | "structured"
  | "app_friendly"
  | "ghost";

export type TemplateProfile =
  | "standard"
  | "max_fee"
  | "strict"
  | "clean_block"
  | "structured"
  | "app_friendly"
  | "ghost_block";

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

export interface SettlementBatch {
  batch_id: string;
  settlement_class: string;
  epoch_id: number;
  status: string;
  participant_count: number;
  signatures_collected: number;
  your_lock_id?: string | null;
  your_signature_submitted?: boolean;
  txid?: string | null;
  confirmations?: number;
  created_at?: number;
  total_amount_sats?: number;
  l1_txid?: string | null;
  finalized_at?: number | null;
}

export interface SettlementStats {
  pending_batches?: number;
  active_batches?: number;
  confirmed_24h?: number;
  total_settled_24h?: number;
  your_settlements?: number;
  current_epoch?: number;
  l1_connected?: boolean;
  l1_height?: number;
}

export interface SettlementResponse {
  // Backend fields
  status?: string;
  pending_settlements?: number;
  pending_count?: number;
  batches_24h?: number;
  last_settlement?: Record<string, unknown> | null;
  total_settled_sats?: number;
  // Dashboard aliases
  batches?: SettlementBatch[];
  stats?: SettlementStats;
}

// Node-level settlement service status
export interface SettlementStatus {
  l1_available?: boolean;
  l1_height?: number;
  active_count?: number;
  pending_count?: number;
  batches_24h?: number;
  total_settled_24h?: number;
  current_epoch?: number;
  avg_batch_size?: number;
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
export interface BackupOptions {
  include_identity?: boolean;
  include_wallet_keys?: boolean;
  include_config?: boolean;
  include_ghost_pay_db?: boolean;
  include_block_history?: boolean;
  include_logs?: boolean;
}

export interface BackupInfo {
  node_id?: string;
  elder_status?: boolean;
  elder_slot?: number | null;
  config_included?: boolean;
  ghost_pay_blocks?: number | null;
  locks_count?: number;
  locks_balance_btc?: number;
  created_at?: number;
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
  download_url?: string;
}

export interface VerifyBackupResponse {
  valid?: boolean;
  info?: BackupInfo | null;
  error?: string | null;
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
