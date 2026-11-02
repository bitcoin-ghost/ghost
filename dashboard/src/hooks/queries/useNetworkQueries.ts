import { useQuery } from '@tanstack/react-query';
import { getPoolStatus, getPeers } from '@/lib/api/network';

export const networkKeys = {
  all: ['network'] as const,
  pool: () => [...networkKeys.all, 'pool'] as const,
  peers: () => [...networkKeys.all, 'peers'] as const,
};

export function usePoolStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: networkKeys.pool(),
    queryFn: getPoolStatus,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function usePeers(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: networkKeys.peers(),
    queryFn: getPeers,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}
