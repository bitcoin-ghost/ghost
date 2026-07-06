import { useQuery } from '@tanstack/react-query';
import { getMeshStatus, type MeshResponse } from '@/lib/api/mesh';
import { fetchMeshNodes, type MeshNodesResponse } from '@/lib/api/meshNodes';

export const meshKeys = {
  all: ['mesh'] as const,
  status: () => [...meshKeys.all, 'status'] as const,
  nodes: () => [...meshKeys.all, 'nodes'] as const,
};

export function useMeshStatus() {
  return useQuery<MeshResponse>({
    queryKey: meshKeys.status(),
    queryFn: getMeshStatus,
    refetchInterval: 30000, // Refresh every 30 seconds
    staleTime: 10000,
  });
}

/**
 * Live mesh-node list from `/api/v1/pool/mesh-nodes` (self + every connected
 * peer, each with its REAL public `address`). This is the source the Capacity
 * and Geo pages share — unlike `/api/v1/network/peers`, whose `address` is
 * empty.
 */
export function useMeshNodes(options?: { refetchInterval?: number }) {
  return useQuery<MeshNodesResponse>({
    queryKey: meshKeys.nodes(),
    queryFn: fetchMeshNodes,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
