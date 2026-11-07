import { useQuery, useQueries } from "@tanstack/react-query";
import { getPoolMiner, getPoolMinerHistory, getPoolMinerList, getPoolStatus, type PoolHistoryWindow } from "@/lib/api/pool";

export const poolKeys = {
  all: ["pool"] as const,
  status: () => [...poolKeys.all, "status"] as const,
  minerList: () => [...poolKeys.all, "miner-list"] as const,
  miner: (address: string) => [...poolKeys.all, "miner", address] as const,
  history: (address: string, window: PoolHistoryWindow) => [...poolKeys.all, "history", address, window] as const,
};

/** The pool-wide status. Retried once: an unavailable pool_sv2 shows as such quickly. */
export function usePoolStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: poolKeys.status(),
    queryFn: getPoolStatus,
    refetchInterval: options?.refetchInterval ?? 15_000,
    retry: 1,
  });
}

/** Every active payout address on this node (operator only). */
export function usePoolMinerList() {
  return useQuery({
    queryKey: poolKeys.minerList(),
    queryFn: getPoolMinerList,
    refetchInterval: 15_000,
    retry: 1,
  });
}

export function usePoolMiner(address: string | null) {
  return useQuery({
    queryKey: poolKeys.miner(address ?? ""),
    queryFn: () => getPoolMiner(address as string),
    enabled: !!address,
    refetchInterval: 30_000,
    retry: 1,
  });
}

export function usePoolMinerHistory(address: string | null, window: PoolHistoryWindow) {
  return useQuery({
    queryKey: poolKeys.history(address ?? "", window),
    queryFn: () => getPoolMinerHistory(address as string, window),
    enabled: !!address,
    refetchInterval: 60_000,
    retry: 1,
  });
}

/** The miner answers for every address in `addresses`, in the same order. */
export function usePoolMiners(addresses: string[]) {
  return useQueries({
    queries: addresses.map((a) => ({
      queryKey: poolKeys.miner(a),
      queryFn: () => getPoolMiner(a),
      refetchInterval: 30_000,
      retry: 1,
    })),
  });
}
