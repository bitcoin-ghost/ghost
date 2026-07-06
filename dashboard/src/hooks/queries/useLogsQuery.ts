import { useQuery } from '@tanstack/react-query';
import { getLogs, getLogUnits } from '@/lib/api/logs';

export const logsKeys = {
  all: ['logs'] as const,
  list: (params?: { limit?: number; level?: string; unit?: string }) =>
    [...logsKeys.all, 'list', params] as const,
  units: () => [...logsKeys.all, 'units'] as const,
};

export function useLogs(params?: { limit?: number; level?: string; unit?: string }) {
  return useQuery({
    queryKey: logsKeys.list(params),
    queryFn: () => getLogs(params?.limit, params?.level, params?.unit),
    refetchInterval: false, // Manual refresh or WebSocket
  });
}

export function useLogUnits() {
  return useQuery({
    queryKey: logsKeys.units(),
    queryFn: () => getLogUnits(),
    staleTime: 5 * 60 * 1000, // Unit list changes rarely.
  });
}
