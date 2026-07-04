// Mining API endpoints
import { fetchApi } from './client';
import type { MiningStatus, MinersResponse, BestHashResponse } from '@/types/api';

export async function getMiningStatus(): Promise<MiningStatus> {
  return fetchApi<MiningStatus>('/api/v1/mining/status');
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

// Public mining node info (advertised via P2P)
export interface PublicMiningNode {
  node_id: string;
  host: string;
  sv1_port: number;
  sv2_port: number;
  region: string;
  mempool_policy: string;
  capacity: number;
  last_seen: number;
}

export interface PublicMiningNodesResponse {
  nodes: PublicMiningNode[];
  total: number;
  data_source: string;
  status_message: string | null;
}

export async function getPublicMiningNodes(): Promise<PublicMiningNodesResponse> {
  return fetchApi<PublicMiningNodesResponse>('/api/v1/mining/public-nodes');
}
