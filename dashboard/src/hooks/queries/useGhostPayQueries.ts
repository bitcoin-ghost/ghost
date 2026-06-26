import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getGhostPayStatus,
  getWraithSessions,
  getWraithStats,
  getGhostLocks,
  getPayments,
  getSettlement,
  getSettlementStatus,
  getGhostPayPayoutHistory,
  joinWraithSession,
  requestLockSettlement,
  useLockInMix as apiUseLockInMix,
  createLock,
  reconcileLock,
  getGhostId,
} from '@/lib/api/ghostpay';
import type {
  LockDenomination,
  TimelockTier,
  SettlementClass,
} from '@/lib/api/ghostpay';
import type { PayoutHistoryTimeFilter } from '@/types/api';

export const ghostPayKeys = {
  all: ['ghostpay'] as const,
  status: () => [...ghostPayKeys.all, 'status'] as const,
  wraith: () => [...ghostPayKeys.all, 'wraith'] as const,
  wraithStats: () => [...ghostPayKeys.all, 'wraith-stats'] as const,
  locks: () => [...ghostPayKeys.all, 'locks'] as const,
  payments: (params?: { limit?: number; offset?: number }) =>
    [...ghostPayKeys.all, 'payments', params] as const,
  settlement: () => [...ghostPayKeys.all, 'settlement'] as const,
  settlementStatus: () => [...ghostPayKeys.all, 'settlement-status'] as const,
  payoutHistory: (timeFilter: PayoutHistoryTimeFilter) =>
    [...ghostPayKeys.all, 'payout-history', timeFilter] as const,
  ghostId: () => [...ghostPayKeys.all, 'ghost-id'] as const,
};

export function useGhostId(options?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ghostPayKeys.ghostId(),
    queryFn: getGhostId,
    enabled: options?.enabled ?? true,
    staleTime: Infinity,
  });
}

export function useGhostPayStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.status(),
    queryFn: getGhostPayStatus,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useWraithSessions(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.wraith(),
    queryFn: getWraithSessions,
    refetchInterval: options?.refetchInterval ?? 5_000,
  });
}

export function useGhostLocks(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.locks(),
    queryFn: getGhostLocks,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function usePayments(params?: { limit?: number; offset?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.payments(params),
    queryFn: () => getPayments(params?.limit, params?.offset),
    refetchInterval: 10_000,
  });
}

export function useSettlement(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.settlement(),
    queryFn: getSettlement,
    refetchInterval: options?.refetchInterval ?? 5_000,
  });
}

// Mutations
export function useJoinWraithSession() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ sessionId, lockId }: { sessionId: string; lockId: string }) =>
      joinWraithSession(sessionId, lockId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.wraith() });
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.locks() });
    },
  });
}

export function useRequestLockSettlement() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (lockId: string) => requestLockSettlement(lockId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.locks() });
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.settlement() });
    },
  });
}

export function useUseLockInMix() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ lockId, sessionId }: { lockId: string; sessionId: string }) =>
      apiUseLockInMix(lockId, sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.locks() });
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.wraith() });
    },
  });
}

export function useCreateLock() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (config: { denomination: LockDenomination; timelock_tier: TimelockTier }) =>
      createLock(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.locks() });
    },
  });
}

export function useReconcileLock() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      lockId,
      destinationAddress,
      settlementClass,
    }: {
      lockId: string;
      destinationAddress: string;
      settlementClass: SettlementClass;
    }) =>
      reconcileLock(lockId, {
        destination_address: destinationAddress,
        settlement_class: settlementClass,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.locks() });
      queryClient.invalidateQueries({ queryKey: ghostPayKeys.settlement() });
    },
  });
}

// New node-focused queries

export function useWraithStats(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.wraithStats(),
    queryFn: getWraithStats,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useSettlementStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: ghostPayKeys.settlementStatus(),
    queryFn: getSettlementStatus,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}

export function useGhostPayPayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d',
  options?: { refetchInterval?: number }
) {
  return useQuery({
    queryKey: ghostPayKeys.payoutHistory(timeFilter),
    queryFn: () => getGhostPayPayoutHistory(timeFilter),
    refetchInterval: options?.refetchInterval ?? 60_000, // 1 minute
  });
}
