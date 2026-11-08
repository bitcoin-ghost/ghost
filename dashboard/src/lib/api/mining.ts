// Mining API endpoints
import { fetchApi } from './client';
import type {
  MiningStatus,
  BestHashResponse,
  PoolSeriesResponse,
  MiningCoinbaseResponse,
} from '@/types/api';

export async function getMiningStatus(): Promise<MiningStatus> {
  return fetchApi<MiningStatus>('/api/v1/mining/status');
}

// Snapshot of the block template this node is currently building.
export interface BlockTemplateSnapshot {
  height: number;
  job_id: string;
  prev_hash: string;
  tx_count: number; // includes coinbase
  total_fees_sat: number;
  subsidy_sat: number;
  coinbase_value_sat: number; // subsidy + fees
  total_weight: number; // weight units (max 4,000,000)
  ntime: number; // template time (Unix seconds)
  nbits: string;
  version: number;
  refresh_secs: number;
}
export interface MiningTemplateResponse {
  available: boolean;
  template: BlockTemplateSnapshot | null;
}
export async function getMiningTemplate(): Promise<MiningTemplateResponse> {
  return fetchApi<MiningTemplateResponse>('/api/v1/mining/template');
}

// Coinbase payout breakdown for the block above — how the coinbase splits
// into the treasury's base share, the miners' share and the finder's tx fees. The
// Next.js proxy signs this GET with the operator INTERNAL_AUTH_KEY, so an
// authed operator gets the full unredacted recipient lists; unsigned/pre-
// redeploy nodes return `addresses_redacted: true` (amounts only).
export async function getMiningCoinbase(): Promise<MiningCoinbaseResponse> {
  return fetchApi<MiningCoinbaseResponse>('/api/v1/mining/coinbase');
}

// Rolling server-side time-series of pool hashrate + connected miners.
// `window` is '1h' or '24h'. Empty samples until the node has been up long
// enough to accumulate history (the mempool page falls back to its session buffer).
export async function getPoolSeries(
  window: '1h' | '24h' = '1h',
): Promise<PoolSeriesResponse> {
  return fetchApi<PoolSeriesResponse>(`/api/v1/pool/series?window=${window}`);
}

export async function getBestHash(): Promise<BestHashResponse> {
  return fetchApi<BestHashResponse>('/api/v1/mining/best-hash');
}
