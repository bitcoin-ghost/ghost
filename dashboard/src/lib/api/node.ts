// Node API endpoints
import { fetchApi } from './client';
import type { NodeInfo, NodeStatus, HealthStatus, BlockchainStatus, ChainHealthResponse } from '@/types/api';

export async function getNodeInfo(): Promise<NodeInfo> {
  return fetchApi<NodeInfo>('/api/v1/node/info');
}

// Chain health: current tip-lag status + recently recorded reorg events.
// Persisted server-side (bounded ring), so the Sync page can SEE reorgs and
// tip-lag rather than these only firing operator alerts.
export async function getChainHealth(): Promise<ChainHealthResponse> {
  return fetchApi<ChainHealthResponse>('/api/v1/chain/health');
}

export async function getNodeStatus(): Promise<NodeStatus> {
  return fetchApi<NodeStatus>('/api/v1/node/status');
}

// Chain & sync status from ghostd `getblockchaininfo`.
export async function getBlockchainStatus(): Promise<BlockchainStatus> {
  return fetchApi<BlockchainStatus>('/api/v1/node/blockchain');
}

export async function getHealth(): Promise<HealthStatus> {
  // /health wraps its payload in a SignedResponse envelope: { response, signed }.
  // Unwrap so callers see the flat HealthStatus shape (healthy, uptime, …).
  const raw = await fetchApi<HealthStatus & { response?: HealthStatus }>('/health');
  return raw?.response ?? raw;
}

// Nickname (new)
export async function getNickname(): Promise<{ nickname: string }> {
  return fetchApi<{ nickname: string }>('/api/v1/node/nickname');
}

export async function setNickname(nickname: string): Promise<{ nickname: string }> {
  return fetchApi<{ nickname: string }>('/api/v1/node/nickname', {
    method: 'POST',
    body: JSON.stringify({ nickname }),
  });
}
