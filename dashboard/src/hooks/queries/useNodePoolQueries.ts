import { useQuery, useQueries } from "@tanstack/react-query";
import { getNodePoolStatus, getNodePoolLedger, getNodePoolMiner } from "@/lib/api/nodePool";

export const nodePoolKeys = {
  all: ["node-pool"] as const,
  status: () => [...nodePoolKeys.all, "status"] as const,
  ledger: (address: string) => [...nodePoolKeys.all, "ledger", address] as const,
  miner: (address: string) => [...nodePoolKeys.all, "miner", address] as const,
};

/** The pool-wide status. Not retried on failure: an unavailable pool_sv2 shows as such at once. */
export function useNodePoolStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: nodePoolKeys.status(),
    queryFn: getNodePoolStatus,
    refetchInterval: options?.refetchInterval ?? 15_000,
    retry: 1,
  });
}

export function useNodePoolLedger(address: string | null) {
  return useQuery({
    queryKey: nodePoolKeys.ledger(address ?? ""),
    queryFn: () => getNodePoolLedger(address as string),
    enabled: !!address,
    refetchInterval: 30_000,
    retry: 1,
  });
}

export function useNodePoolMiner(address: string | null) {
  return useQuery({
    queryKey: nodePoolKeys.miner(address ?? ""),
    queryFn: () => getNodePoolMiner(address as string),
    enabled: !!address,
    refetchInterval: 30_000,
    retry: 1,
  });
}

/** Ledger and miner answers for every address in `addresses`, in the same order. */
export function useNodePoolAddresses(addresses: string[]) {
  const ledgers = useQueries({
    queries: addresses.map((a) => ({
      queryKey: nodePoolKeys.ledger(a),
      queryFn: () => getNodePoolLedger(a),
      refetchInterval: 30_000,
      retry: 1,
    })),
  });
  const miners = useQueries({
    queries: addresses.map((a) => ({
      queryKey: nodePoolKeys.miner(a),
      queryFn: () => getNodePoolMiner(a),
      refetchInterval: 30_000,
      retry: 1,
    })),
  });
  return { ledgers, miners };
}
