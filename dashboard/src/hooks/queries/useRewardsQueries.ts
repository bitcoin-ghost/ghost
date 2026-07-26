import { useQuery } from '@tanstack/react-query';
import { getRewardsCurrent, getRewardsHistory, getRewardsFull, getNodePayoutHistory, getNodeBalances, getNodePayoutEvents } from '@/lib/api/rewards';
import type { PayoutHistoryTimeFilter } from '@/types/api';

export const rewardsKeys = {
  all: ['rewards'] as const,
  current: () => [...rewardsKeys.all, 'current'] as const,
  history: () => [...rewardsKeys.all, 'history'] as const,
  full: () => [...rewardsKeys.all, 'full'] as const,
  nodeHistory: (timeFilter: PayoutHistoryTimeFilter, payoutType?: string) =>
    [...rewardsKeys.all, 'node-history', timeFilter, payoutType] as const,
  nodePayoutEvents: (timeFilter: PayoutHistoryTimeFilter) =>
    [...rewardsKeys.all, 'node-payout-events', timeFilter] as const,
  nodeBalances: () => [...rewardsKeys.all, 'node-balances'] as const,
};

export function useRewardsCurrent(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.current(),
    queryFn: getRewardsCurrent,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

export function useRewardsHistory(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.history(),
    queryFn: getRewardsHistory,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

export function useRewardsFull(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.full(),
    queryFn: getRewardsFull,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}

// Alias for convenience
export const useRewards = useRewardsFull;

export function useNodePayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d',
  payoutType?: string,
  options?: { refetchInterval?: number }
) {
  return useQuery({
    queryKey: rewardsKeys.nodeHistory(timeFilter, payoutType),
    queryFn: () => getNodePayoutHistory(timeFilter, payoutType),
    refetchInterval: options?.refetchInterval ?? 60_000, // 1 minute
  });
}

// Per-event node payout history. Served only by node binaries new enough to
// expose /api/v1/rewards/node-payout-events; on older nodes this 404s and the
// query lands in `isError`, so the pool page falls back to the balance ledger.
// We don't retry (a 404 won't fix itself) to avoid hammering the endpoint.
export function useNodePayoutEvents(
  timeFilter: PayoutHistoryTimeFilter = '7d',
  options?: { refetchInterval?: number }
) {
  return useQuery({
    queryKey: rewardsKeys.nodePayoutEvents(timeFilter),
    queryFn: () => getNodePayoutEvents(timeFilter),
    refetchInterval: options?.refetchInterval ?? 60_000,
    retry: false,
  });
}

export function useNodeBalances(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: rewardsKeys.nodeBalances(),
    queryFn: getNodeBalances,
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
