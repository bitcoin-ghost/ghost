import { useQuery } from '@tanstack/react-query';
import { getHazeStatus, getLegalPacket, getCheckpointStatus } from '@/lib/api/haze';

export const hazeKeys = {
  all: ['haze'] as const,
  status: () => [...hazeKeys.all, 'status'] as const,
  legalPacket: () => [...hazeKeys.all, 'legal-packet'] as const,
  checkpoint: () => [...hazeKeys.all, 'checkpoint'] as const,
};

export function useHazeStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: hazeKeys.status(),
    queryFn: getHazeStatus,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

export function useLegalPacket(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: hazeKeys.legalPacket(),
    queryFn: getLegalPacket,
    refetchInterval: options?.refetchInterval ?? 60_000,
  });
}

export function useCheckpointStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: hazeKeys.checkpoint(),
    queryFn: getCheckpointStatus,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
