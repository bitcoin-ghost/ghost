// Node API endpoints
import { fetchApi } from './client';
import type { NodeInfo, NodeStatus, SharesInfo, HealthStatus, BlockchainStatus } from '@/types/api';

export async function getNodeInfo(): Promise<NodeInfo> {
  return fetchApi<NodeInfo>('/api/v1/node/info');
}

export async function getNodeStatus(): Promise<NodeStatus> {
  return fetchApi<NodeStatus>('/api/v1/node/status');
}

// Chain & sync status from ghostd `getblockchaininfo`.
export async function getBlockchainStatus(): Promise<BlockchainStatus> {
  return fetchApi<BlockchainStatus>('/api/v1/node/blockchain');
}

export async function getShares(): Promise<SharesInfo> {
  // /api/v1/node/shares reports CLAIMED capabilities (e.g. archive_mode:true,
  // total:15) which is NOT what the node earns. /health reports the VERIFIED
  // capabilities the node has actually proved and is paid for. Prefer the
  // verified view for the capability booleans and total; keep the shares
  // endpoint for fields it alone provides (uptime, elder slot, est. reward).
  const [claimed, health] = await Promise.all([
    fetchApi<SharesInfo>('/api/v1/node/shares'),
    getHealth().catch(() => null),
  ]);

  const caps = health?.capabilities;
  if (!caps) return claimed;

  return {
    ...claimed,
    archive_mode: caps.archive_mode ?? claimed.archive_mode,
    ghost_pay: caps.ghost_pay ?? claimed.ghost_pay,
    public_mining: caps.public_mining ?? claimed.public_mining,
    reaper: caps.reaper ?? claimed.reaper,
    elder: caps.elder_status ?? claimed.elder,
    total: caps.total_shares ?? claimed.total,
  };
}

export async function getHealth(): Promise<HealthStatus> {
  // /health wraps its payload in a SignedResponse envelope: { response, signed }.
  // Unwrap so callers see the flat HealthStatus shape (healthy, capabilities, …).
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
