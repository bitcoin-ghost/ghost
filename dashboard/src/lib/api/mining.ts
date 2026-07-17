// Mining API endpoints
import { fetchApi } from './client';
import type {
  MiningStatus,
  MinersResponse,
  BestHashResponse,
  PoolSeriesResponse,
  MeshLeaderboardResponse,
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

// Rolling server-side time-series of pool hashrate + connected miners.
// `window` is '1h' or '24h'. Empty samples until the node has been up long
// enough to accumulate history (the pool page falls back to its session buffer).
export async function getPoolSeries(
  window: '1h' | '24h' = '1h',
): Promise<PoolSeriesResponse> {
  return fetchApi<PoolSeriesResponse>(`/api/v1/pool/series?window=${window}`);
}

// Mesh-wide leaderboard: nodes ranked by hashrate across the whole mesh, plus
// mesh-wide best-share records per window.
export async function getPoolMeshLeaderboard(): Promise<MeshLeaderboardResponse> {
  return fetchApi<MeshLeaderboardResponse>('/api/v1/pool/mesh-leaderboard');
}

export async function getMiners(): Promise<MinersResponse> {
  // Dual-mode endpoint: the Next.js proxy signs this GET with the operator
  // INTERNAL_AUTH_KEY (HMAC over an empty body), so the node returns the FULL
  // unredacted connected-miner list (`miners_redacted: false`). Pre-redeploy
  // nodes — or an unsigned request — get the redacted aggregate instead, which
  // the mining page renders as an aggregate count rather than a table.
  return fetchApi<MinersResponse>('/api/v1/mining/miners');
}

export async function getBestHash(): Promise<BestHashResponse> {
  return fetchApi<BestHashResponse>('/api/v1/mining/best-hash');
}

export async function setPrivateMining(enabled: boolean): Promise<MiningStatus> {
  return fetchApi<MiningStatus>('/api/v1/mining/private', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

export async function setPublicMining(enabled: boolean): Promise<MiningStatus> {
  return fetchApi<MiningStatus>('/api/v1/mining/public', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  });
}

export async function setPayoutAddress(address: string | null): Promise<MiningStatus> {
  return fetchApi<MiningStatus>('/api/v1/mining/payout_address', {
    method: 'POST',
    body: JSON.stringify({ address }),
  });
}

