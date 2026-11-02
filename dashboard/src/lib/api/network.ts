// Network API endpoints
import { fetchApi } from './client';
import type {
  PoolStatus,
  PeersResponse,
} from '@/types/api';

export async function getPoolStatus(): Promise<PoolStatus> {
  return fetchApi<PoolStatus>('/api/v1/network/pool');
}

export async function getPeers(): Promise<PeersResponse> {
  const data = await fetchApi<PeersResponse & { peer_count?: number }>('/api/v1/network/peers');
  // Backend may return peer_count instead of total
  if (data.total === undefined && data.peer_count !== undefined) {
    data.total = data.peer_count;
  }
  return data;
}
