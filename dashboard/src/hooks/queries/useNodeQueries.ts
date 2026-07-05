import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getNodeInfo, getNodeStatus, getBlockchainStatus, getShares, getHealth, getNickname, setNickname } from '@/lib/api/node';
import { useNodeStore } from '@/stores';

// Query keys for consistency
export const nodeKeys = {
  all: ['node'] as const,
  info: () => [...nodeKeys.all, 'info'] as const,
  status: () => [...nodeKeys.all, 'status'] as const,
  blockchain: () => [...nodeKeys.all, 'blockchain'] as const,
  shares: () => [...nodeKeys.all, 'shares'] as const,
  health: () => [...nodeKeys.all, 'health'] as const,
  nickname: () => [...nodeKeys.all, 'nickname'] as const,
};

export function useNodeInfo() {
  const setNodeInfo = useNodeStore((s) => s.setNodeInfo);

  return useQuery({
    queryKey: nodeKeys.info(),
    queryFn: getNodeInfo,
    staleTime: 60_000, // 1 minute
    select: (data) => {
      setNodeInfo(data);
      return data;
    },
  });
}

export function useNodeStatus(options?: { refetchInterval?: number }) {
  const setNodeStatus = useNodeStore((s) => s.setNodeStatus);

  return useQuery({
    queryKey: nodeKeys.status(),
    queryFn: getNodeStatus,
    refetchInterval: options?.refetchInterval ?? 10_000, // Poll every 10 seconds
    select: (data) => {
      setNodeStatus(data);
      return data;
    },
  });
}

export function useBlockchainStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: nodeKeys.blockchain(),
    queryFn: getBlockchainStatus,
    refetchInterval: options?.refetchInterval ?? 10_000, // Poll every 10 seconds
  });
}

export function useShares() {
  const setShares = useNodeStore((s) => s.setShares);

  return useQuery({
    queryKey: nodeKeys.shares(),
    queryFn: getShares,
    staleTime: 30_000, // 30 seconds
    select: (data) => {
      setShares(data);
      return data;
    },
  });
}

export function useHealth() {
  return useQuery({
    queryKey: nodeKeys.health(),
    queryFn: getHealth,
    refetchInterval: 30_000, // Poll every 30 seconds
  });
}

export function useNickname() {
  return useQuery({
    queryKey: nodeKeys.nickname(),
    queryFn: getNickname,
    staleTime: 60_000,
  });
}

export function useSetNickname() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (nickname: string) => setNickname(nickname),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: nodeKeys.nickname() });
    },
  });
}
