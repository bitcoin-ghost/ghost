import { useQuery } from '@tanstack/react-query';
import { fetchMeshNodes, type MeshNodesResponse } from '@/lib/api/meshNodes';

export const meshKeys = {
  all: ['mesh'] as const,
  nodes: () => [...meshKeys.all, 'nodes'] as const,
};

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
