// Ghost Pool API.
//
// pool_sv2 builds these answers on its loopback monitoring listener; the node backend (:8080)
// forwards them unchanged:
//   GET /api/v1/pool/status                         the pool-wide view of this node
//   GET /api/v1/miner/{address}                     one miner: workers, best shares, blocks found
//   GET /api/v1/miner/{address}/history?window=...  the same over time
// The shapes below follow the module docs of `bins/pool-sv2/src/lib/solo_api.rs`. pool_sv2 not
// answering is a 503 from the backend, which `fetchApi` turns into a thrown Error: the pages show
// that as "unavailable", never as zero.

import { fetchApi } from "./client";

/** Hashes per second over three spans; `null` when the pool observed less than a minute of it. */
export interface PoolRates {
  "15m": number | null;
  "1h": number | null;
  "24h": number | null;
}

/** Best share difficulties (difficulty-1 units); `0` means none yet. */
export interface PoolBestShare {
  ever: number;
  "24h": number;
}

/** Share counts over the last 24 hours. */
export interface PoolCounts {
  accepted: number;
  stale: number;
  rejected: number;
  reject_reasons: Record<string, number>;
}

/** What another node said to a found block it was sent. */
export interface PoolSubmitResult {
  /** `scheme://host:port`, never its credentials. */
  node: string;
  /** `accepted`, `duplicate`, or the error. */
  result: string;
}

/** One block this pool found, recorded when it was submitted. */
export interface PoolFoundBlock {
  height: number;
  hash: string;
  /** The finder's payout address. */
  address: string;
  /** The finder's worker name; empty when it has none. */
  worker: string;
  /** What the coinbase paid the finder: `subsidy - subsidy / 200 + fees`. */
  reward_sats: number;
  /** What it paid the treasury: `subsidy / 200`. */
  treasury_sats: number;
  fees_sats: number;
  found_at: number;
  /** The post-submit coinbase check: `ok`, what was wrong, or `null` until it has run. */
  check: string | null;
  submitted: PoolSubmitResult[];
}

export interface PoolFeePolicy {
  treasury_address: string;
  treasury_share_of_subsidy: number;
  treasury_sats_next_block: number | null;
  miner_sats_next_block_before_fees: number | null;
  /** Always `miner`. */
  fees_to: string;
}

/** `GET /api/v1/pool/status`. */
export interface PoolStatus {
  network: string;
  generated_at: number;
  collecting_since: number;
  bitcoin: {
    tip_height: number | null;
    tip_hash: string | null;
    job_height: number | null;
    network_difficulty: number | null;
  };
  miners: {
    /** Distinct payout addresses with an open channel. */
    connected: number;
    /** Open channels. */
    workers: number;
  };
  pool_hashrate_hs: PoolRates;
  best_share: PoolBestShare;
  /** Every block this pool found, oldest first. */
  blocks_found: PoolFoundBlock[];
  fee_policy: PoolFeePolicy;
  ports: { sv1: number[]; sv2: number };
  /** The other nodes every found block is also sent to, as `scheme://host:port`. */
  submit_nodes: string[];
}

export interface PoolConnection {
  downstream_id: number;
  channel_id: number;
  /** `standard` or `extended`. */
  kind: string;
}

export interface PoolWorker {
  name: string;
  /** `online`, `idle` or `offline`. */
  status: string;
  last_share_at: number | null;
  last_submit_at: number | null;
  hashrate_hs: PoolRates;
  shares_24h: PoolCounts;
  best_share: PoolBestShare;
  connections: PoolConnection[];
}

export interface PoolExpectedTime {
  known: boolean;
  /** Mean seconds to a block: `network_difficulty * 2^32 / hashrate_hs`. */
  seconds: number | null;
  hashrate_hs: number | null;
  /** `1h` or `24h`. */
  hashrate_window: string | null;
  network_difficulty: number | null;
  reason: string | null;
}

/** `GET /api/v1/miner/{address}`. */
export interface PoolMiner {
  address: string;
  network: string;
  script_hex: string;
  generated_at: number;
  collecting_since: number;
  summary: {
    workers: number;
    online: number;
    idle: number;
    offline: number;
    hashrate_hs: PoolRates;
    shares_24h: PoolCounts;
    last_share_at: number | null;
    best_share: PoolBestShare;
  };
  /** Online first. */
  workers: PoolWorker[];
  /** This address's blocks, oldest first. */
  blocks_found: PoolFoundBlock[];
  expected_time_to_block: PoolExpectedTime;
}

export interface PoolSeries {
  hashrate_hs: (number | null)[];
  accepted: (number | null)[];
  stale: (number | null)[];
  rejected: (number | null)[];
  best_share: (number | null)[];
}

export type PoolHistoryWindow = "24h" | "7d" | "30d";

/** `GET /api/v1/miner/{address}/history?window=24h|7d|30d`. A `null` is a bucket the pool was
 *  not collecting in: unknown, not zero. */
export interface PoolHistory {
  address: string;
  network: string;
  window: PoolHistoryWindow;
  bucket_seconds: number;
  generated_at: number;
  collecting_since: number;
  buckets: number[];
  total: PoolSeries;
  workers: { name: string; series: PoolSeries }[];
  workers_omitted: number;
  reject_reasons: Record<string, number>;
}

export async function getPoolStatus(): Promise<PoolStatus> {
  return fetchApi<PoolStatus>("/api/v1/pool/status");
}

export async function getPoolMiner(address: string): Promise<PoolMiner> {
  return fetchApi<PoolMiner>(`/api/v1/miner/${encodeURIComponent(address)}`);
}

export async function getPoolMinerHistory(address: string, window: PoolHistoryWindow): Promise<PoolHistory> {
  return fetchApi<PoolHistory>(`/api/v1/miner/${encodeURIComponent(address)}/history?window=${window}`);
}
