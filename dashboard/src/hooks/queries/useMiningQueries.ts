import { useQuery } from '@tanstack/react-query';
import { getMiningStatus, getMiningTemplate, getMiningCoinbase, getBestHash, getPoolSeries } from '@/lib/api/mining';

export const miningKeys = {
  all: ['mining'] as const,
  status: () => [...miningKeys.all, 'status'] as const,
  bestHash: () => [...miningKeys.all, 'best-hash'] as const,
  poolSeries: (window: string) => [...miningKeys.all, 'pool-series', window] as const,
};

// Server-side time-series ring (the mempool page reads its mempool samples).
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

export function useMiningTemplate(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ["mining", "template"],
    queryFn: getMiningTemplate,
    refetchInterval: options?.refetchInterval ?? 5_000,
  });
}

export function useMiningCoinbase(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ["mining", "coinbase"],
    queryFn: getMiningCoinbase,
    refetchInterval: options?.refetchInterval ?? 5_000,
  });
}

export function useMiningStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: miningKeys.status(),
    queryFn: getMiningStatus,
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
