import { useQuery } from "@tanstack/react-query";
import { getReaperStatus } from "@/lib/api/reaper";

export const reaperKeys = {
  all: ["reaper"] as const,
  status: () => [...reaperKeys.all, "status"] as const,
};

export function useReaperStatus(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: reaperKeys.status(),
    queryFn: getReaperStatus,
    refetchInterval: options?.refetchInterval ?? 10_000,
  });
}
