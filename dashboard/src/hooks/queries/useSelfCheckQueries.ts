import { useQuery } from "@tanstack/react-query";
import { getSelfCheck } from "@/lib/api/selfCheck";

export const selfCheckKeys = {
  all: ["selfCheck"] as const,
  status: () => [...selfCheckKeys.all, "status"] as const,
};

export function useSelfCheck(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: selfCheckKeys.status(),
    queryFn: getSelfCheck,
    // The backend probes every 30s; poll at the same cadence.
    refetchInterval: options?.refetchInterval ?? 30_000,
  });
}
