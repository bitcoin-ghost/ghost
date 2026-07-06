import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getMiningStatus, getMiners, getBestHash, getPublicMiningNodes, setPrivateMining, setPublicMining, setPayoutAddress, getPoolSeries, getPoolMeshLeaderboard } from '@/lib/api/mining';

export const miningKeys = {
  all: ['mining'] as const,
  status: () => [...miningKeys.all, 'status'] as const,
  miners: () => [...miningKeys.all, 'miners'] as const,
  bestHash: () => [...miningKeys.all, 'best-hash'] as const,
  publicNodes: () => [...miningKeys.all, 'public-nodes'] as const,
  poolSeries: (window: string) => [...miningKeys.all, 'pool-series', window] as const,
  meshLeaderboard: () => [...miningKeys.all, 'mesh-leaderboard'] as const,
};

// Server-side pool time-series (hashrate + miners) for the Node Pool charts.
export function usePoolSeriesHistory(
  window: '1h' | '24h' = '1h',
  options?: { refetchInterval?: number },
) {
  return useQuery({
    queryKey: miningKeys.poolSeries(window),
    queryFn: () => getPoolSeries(window),
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

// Mesh-wide leaderboard (node-ranked + mesh best-share records).
export function usePoolMeshLeaderboard(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: miningKeys.meshLeaderboard(),
    queryFn: getPoolMeshLeaderboard,
    refetchInterval: options?.refetchInterval ?? 15_000,
  });
}

export function useMiningStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: miningKeys.status(),
    queryFn: getMiningStatus,
    refetchInterval: options?.refetchInterval ?? 5_000,
  });
}

export function useMiners(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: miningKeys.miners(),
    queryFn: getMiners,
    refetchInterval: options?.refetchInterval ?? 5_000,
  });
}

export function useBestHash(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: miningKeys.bestHash(),
    queryFn: getBestHash,
    refetchInterval: options?.refetchInterval ?? 10_000, // Poll every 10 seconds
  });
}

export function useSetPrivateMining() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setPrivateMining(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: miningKeys.status() });
    },
  });
}

export function useSetPublicMining() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setPublicMining(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: miningKeys.status() });
      // Also invalidate node status since public_mining is part of it
      queryClient.invalidateQueries({ queryKey: ['node', 'status'] });
      queryClient.invalidateQueries({ queryKey: ['config'] });
    },
  });
}

export function useSetPayoutAddress() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (address: string | null) => setPayoutAddress(address),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: miningKeys.status() });
    },
  });
}

export function usePublicMiningNodes(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: miningKeys.publicNodes(),
    queryFn: getPublicMiningNodes,
    refetchInterval: options?.refetchInterval ?? 30_000, // Poll every 30 seconds
  });
}
