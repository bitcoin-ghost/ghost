// Node pool API (W2.11, W2.14, W2.17).
//
// pool_sv2 builds these answers on its loopback monitoring listener; the node backend (:8080)
// forwards them unchanged:
//   GET /api/v1/node-pool/status            -> pool_sv2 /api/v1/node-pool/status
//   GET /api/v1/ledger/{address}            -> pool_sv2 /api/v1/node-pool/ledger/{address}
//   GET /api/v1/miner/{address}             -> pool_sv2 /api/v1/node-pool/miner/{address}
// The shapes below follow `bins/pool-sv2/src/lib/node_pool_api.rs` and `node_pool_miner_api.rs`.
// pool_sv2 not answering is a 503 from the backend, which `fetchApi` turns into a thrown Error:
// the pages show that as "unavailable", never as zero.

import { fetchApi } from "./client";

/** An exact ledger amount: `units` of 2^-32 sat (decimal string) and whole sats (floor). */
export interface NpAmount {
  units: string;
  sats: number;
}

export interface NpStart {
  genesis_anchor: string;
  genesis_btc_height: number;
  /** `config`, `compiled` or `default`. */
  source: string;
  genesis_tier: number;
  genesis_table_digest: string;
  pinned_genesis_table_digest: string | null;
}

export interface NpChain {
  tip: string;
  anchor_height: number;
  btc_height: number;
  t_net: number;
  work: string;
  loose_shares: number;
  unseen_anchors: number;
}

export interface NpRelayStats {
  shares_accepted: number;
  shares_stale: number;
  shares_invalid: number;
  anchors_valid: number;
  anchors_invalid: number;
  reorgs: number;
}

export interface NpCheckpoint {
  anchor: string;
  anchor_height: number;
  btc_height: number;
  digest: string;
  created_at: number;
}

export interface NpRetention {
  checkpoint_depth: number;
  prune: boolean;
  checkpoints: NpCheckpoint[];
}

export interface NpProvisionalBlock {
  height: number;
  block_hash: string;
}

export interface NpSettlement {
  caught_up: boolean;
  synced_height: number | null;
  bitcoin_tip: number | null;
  provisional: NpProvisionalBlock[];
  matched: number;
  confirmed: number;
  mismatched: number;
  disconnected: number;
}

export interface NpPaidOutput {
  address: string;
  sats: number;
}

export interface NpBlock {
  height: number;
  block_hash: string;
  /** `settled` or `provisional`. */
  status: string;
  subsidy_sats: number;
  treasury_base_sats: number;
  miners_paid_sats: number;
  /** Left over while a balance waited: sent to the treasury. */
  treasury_change_sats: number;
  /** Left over after every balance of 1,000 sats or more was paid: sent to the finder. */
  finder_surplus_sats: number;
  treasury_sats: number;
  payouts: NpPaidOutput[];
  applied_at: number;
}

export interface NpSensing {
  model: string;
  firmware: string | null;
  agent: string | null;
  ceiling_class: number;
  settled: boolean;
  highest_passed: number | null;
}

export interface NpMinerChannel {
  downstream_id: number;
  channel_id: number;
  /** `standard` (header only, always the full class) or `extended` (sensed). */
  kind: string;
  address: string;
  worker: string;
  slot_class: number;
  sensing: NpSensing | null;
  firmware_warning: string | null;
}

/** `GET /api/v1/node-pool/status`. Fields added after W2.11 are optional: an older pool_sv2
 *  does not send them, and the pages say "not reported" rather than guess. */
export interface NodePoolStatus {
  network: string;
  node_id?: string | null;
  start: NpStart;
  share_chain: NpChain;
  peers: number;
  relay_stats?: NpRelayStats;
  retention?: NpRetention;
  settlement: NpSettlement;
  fee_address: string;
  ledger_rows: number;
  /** Every pool block since the genesis anchor; `recent_blocks` lists only the latest. */
  pool_blocks_found?: number;
  /** What the pool's credited work over the last day should find: mean seconds between
   *  pool blocks. `null` before any work is credited. */
  pool_expected_block_interval_secs?: number | null;
  /** Every balance summed: what the pool owes its miners now. */
  total_owed?: NpAmount;
  /** The pool's hashrate from credited share work over the last day of Bitcoin blocks. */
  pool_hashrate?: NpPoolHashrate;
  recent_blocks: NpBlock[];
  miners: NpMinerChannel[];
  earning?: NpEarning;
}

/** The pool's hashrate, estimated from the work credited on the share chain: every share
 *  credited on the best chain at a job height in the window, `2^tier` tier-0 shares each, over
 *  the window's Bitcoin blocks at 600 s a block. The same on every node on the same chains. */
export interface NpPoolHashrate {
  /** `null` when it cannot be measured; `unavailable` says why. */
  hashes_per_sec: number | null;
  from_job_height: number | null;
  to_job_height: number | null;
  window_blocks: number;
  credited_shares: number;
  unavailable: string | null;
}

/** Whether work served now earns: nothing before the genesis anchor's height + 21. */
export interface NpEarning {
  first_earning_height: number;
  job_height: number | null;
  earns: boolean | null;
  notice: string | null;
}

export interface NpClassPayout {
  slot_class: number;
  oldest_slots: number;
  in_oldest: boolean;
  sats: number;
}

export interface NpQueue {
  next_block_height: number;
  snapshot_height: number | null;
  parent_anchor: string;
  owed: NpAmount;
  eligible: boolean;
  eligible_count: number;
  is_top: boolean;
  age_rank: number | null;
  size_rank: number | null;
  next_block: NpClassPayout[];
}

export interface NpShare {
  share_id: string;
  anchor: string;
  anchor_btc_height: number;
  job_height: number;
  credited_tier: number;
  credit: NpAmount;
  received_at: number;
}

export interface NpPayout {
  height: number;
  block_hash: string;
  sats: number;
  units: string;
  status: string;
  confirmations: number | null;
  mature: boolean | null;
  applied_at: number;
}

/** `GET /api/v1/ledger/{address}`. */
export interface NodePoolLedger {
  address: string;
  network: string;
  script_hex: string;
  known: boolean;
  message: string | null;
  balance: NpAmount;
  /** The balance carried over at the cutover (the imported genesis table); already in `balance`. */
  genesis?: {
    owed: NpAmount;
    export_height: number;
    queue_since: number | null;
  } | null;
  queue_since: number | null;
  min_payout_sats: number;
  units_per_sat: number;
  queue: NpQueue | null;
  queue_unavailable: string | null;
  recent_shares: NpShare[];
  payouts: NpPayout[];
  settlement: {
    caught_up: boolean;
    synced_height: number | null;
    bitcoin_tip: number | null;
    provisional_blocks: number;
  };
}

/** Hashes per second; `null` when this node observed less than a minute of the span. */
export interface NpRates {
  "15m": number | null;
  "1h": number | null;
  "24h": number | null;
}

export interface NpCounts {
  accepted: number;
  stale: number;
  rejected: number;
  reject_reasons: Record<string, number>;
}

export interface NpConnection {
  downstream_id: number;
  channel_id: number;
  kind: string;
  slot_class: number;
  model: string | null;
  firmware: string | null;
  ceiling_class: number | null;
  settled: boolean | null;
  firmware_warning: string | null;
}

export interface NpWorker {
  name: string;
  /** `online`, `idle` or `offline`. */
  status: string;
  last_share_at: number | null;
  last_submit_at: number | null;
  hashrate_hs: NpRates;
  shares_24h: NpCounts;
  slot_class: number | null;
  firmware_warning: string | null;
  connections: NpConnection[];
}

export interface NpExpectedWait {
  known: boolean;
  reason: string | null;
  seconds: number | null;
  blocks_needed: number | null;
  pool_blocks_counted: number;
  pool_block_interval_secs: number | null;
  typical_outputs_per_block: number | null;
  sats_to_floor: number | null;
  credited_sats_24h: number | null;
  /** How often the pool's credited work should find a block, seconds; null before any credit. */
  pool_expected_block_interval_secs: number | null;
  assumptions: string[];
}

/** `GET /api/v1/miner/{address}`. */
export interface NodePoolMiner {
  address: string;
  network: string;
  script_hex: string;
  node_id: string | null;
  generated_at: number;
  collecting_since: number;
  summary: {
    workers: number;
    online: number;
    idle: number;
    offline: number;
    hashrate_hs: NpRates;
    shares_24h: NpCounts;
    last_share_at: number | null;
  };
  workers: NpWorker[];
  expected_wait: NpExpectedWait;
}

export async function getNodePoolStatus(): Promise<NodePoolStatus> {
  return fetchApi<NodePoolStatus>("/api/v1/node-pool/status");
}

export async function getNodePoolLedger(address: string): Promise<NodePoolLedger> {
  return fetchApi<NodePoolLedger>(`/api/v1/ledger/${encodeURIComponent(address)}`);
}

export async function getNodePoolMiner(address: string): Promise<NodePoolMiner> {
  return fetchApi<NodePoolMiner>(`/api/v1/miner/${encodeURIComponent(address)}`);
}
